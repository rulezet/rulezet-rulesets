rule M_Utility_VIRTUALPEER_1 {
    meta:
        author = "Mandiant"
    strings:
        $vmci_socket_family = {B? 00 00 00 00 B? 02 00 00 00 B? 28 00 00 00 e8 [4-128] B? 00 00 00 00 48 8d [5] b? 00 00 00 00 e8 [4-64] B?  00 00 00 00 48 8d [5] b? 00 00 00 00 e8 [4-64] B? B8 07 00 00 [0-8] b?  00 00 00 00 e8}
        $vmci_socket_marker1 = "/dev/vsock" ascii wide
        $vmci_socket_marker2 = "/vmfs/devices/char/vsock/vsock" ascii wide
        $vmci_socket_init_bind_listen = {e8 [4] 89 45 [4-64] 8B 45 ?? b?  00 00 00 00 b? 01 00 00 00 [0-4] e8 [4-128] B? 10 00 00 00  [1-16] e8 [4-128] BE 01 00 00 00 [1-16] e8 [4] 83 F8 FF}
        $socket_read_write = {BA 01 00 00 00 48 89 CE 89 C7 E8 [4] 48 85 C0 [1-64] BA 01 00 00 00 48 89 CE 89 C7 E8 [4] 48 85 C0 7e ?? eb}
        $marker1 = "nc <port>"
    condition:
        uint32(0) == 0x464c457f and all of them
}