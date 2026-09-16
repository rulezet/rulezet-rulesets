rule DCRat_MsgPack_packets
{
    meta:
        description = "Detects DCRat C2 packet identifiers."
        reference = "ClientSocket.cs"
        
    strings:
        $pkt1 = "Pac_ket" ascii wide
        $pkt2 = "ClientInfo" ascii wide
        $pkt3 = "plu_gin" ascii wide
        $pkt4 = "save_Plugin" ascii wide
        $pkt5 = "Po_ng" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 3 of them
}