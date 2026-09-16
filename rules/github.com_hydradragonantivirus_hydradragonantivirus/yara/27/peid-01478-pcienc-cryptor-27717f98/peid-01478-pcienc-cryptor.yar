rule PEiD_01478_PCIENC_Cryptor_ {
  meta:
    description = "[PCIENC Cryptor]"
    ep_only     = "false"

  strings:
    $a = { 06 50 43 49 45 4E }

  condition:
    $a
}