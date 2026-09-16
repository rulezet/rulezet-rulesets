rule PEiD_01274_Netopsystems_FEAD_Optimizer_ {
  meta:
    description = "[Netopsystems FEAD Optimizer]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 58 BB 00 00 40 00 8B }

  condition:
    $a
}