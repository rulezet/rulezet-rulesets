rule SUSP_LNK_Network_CloudServices_TransferSH_Mutations {
  meta:
    author      = "Greg Lesnewich"
    description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
    date        = "2023-01-03"
    version     = "1.0"
    DaysofYARA  = "3/100"

  strings:
    $transfer_base64                = "transfer.sh" base64 base64wide
    $transfer_xor                   = "transfer.sh" xor(0x01-0xff) ascii wide
    $transfersh_flipflop            = "rtnafsres.h" nocase ascii wide
    $transfersh_reverse             = "hs.refsnart" nocase ascii wide
    $transfersh_hex_enc_str         = "7472616e736665722e7368" nocase ascii wide
    $transfersh_decimal             = "116 114 97 110 115 102 101 114 46 115 104" nocase ascii wide
    $transfersh_fallchill           = "giamhuvi.hs" nocase ascii wide
    $transfersh_stackpush           = "h.shhsferhtran" nocase ascii wide
    $transfersh_stackpushnull       = "h.s\x00hhsferhtran"
    $transfersh_stackpushdoublenull = "h.s\x00\x00hhsferhtran"

  condition:
    uint32be(0x0) == 0x4C000000 and
    1 of them
}