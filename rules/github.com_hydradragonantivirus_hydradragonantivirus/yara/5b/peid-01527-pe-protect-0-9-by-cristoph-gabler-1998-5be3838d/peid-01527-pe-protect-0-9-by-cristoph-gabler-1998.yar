rule PEiD_01527_PE_Protect_0_9_by_Cristoph_Gabler_1998_ {
  meta:
    description = "[PE-Protect 0.9 by Cristoph Gabler 1998]"
    ep_only     = "false"

  strings:
    $a = "PE-PROTECT 0.9"

  condition:
    $a
}