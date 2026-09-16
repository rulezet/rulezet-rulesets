rule PEiD_01366_NX_PE_Packer_v1_0_ {
  meta:
    description = "[NX PE Packer v1.0]"
    ep_only     = "true"

  strings:
    $a = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }

  condition:
    $a
}