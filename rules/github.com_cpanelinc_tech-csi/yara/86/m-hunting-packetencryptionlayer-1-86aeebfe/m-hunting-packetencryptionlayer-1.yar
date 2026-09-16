rule M_Hunting_PacketEncryptionLayer_1 {
    meta:
        author = "Mandiant"
    strings:
        $pel_1 = "pel_client_init"
        $pel_2 = "pel_server_init"
        $pel_3 = "pel_setup_context"
        $pel_4 = "pel_send_msg"
        $pel_5 = "pel_recv_msg"
        $pel_6 = "pel_send_all"
        $pel_7 = "pel_recv_all"
        $pel_8 = "pel_errno"
        $pel_9 = "pel_context"
        $pel_10 = "pel_ctx"
        $pel_11 = "send_ctx"
        $pel_12 = "recv_ctx"
    condition:
        4 of ($pel_*)
}