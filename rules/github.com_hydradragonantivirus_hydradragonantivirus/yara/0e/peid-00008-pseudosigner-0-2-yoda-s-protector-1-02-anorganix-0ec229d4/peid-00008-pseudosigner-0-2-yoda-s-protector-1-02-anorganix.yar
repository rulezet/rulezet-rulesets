rule PEiD_00008___PseudoSigner_0_2__Yoda_s_Protector_1_02______Anorganix_ {
  meta:
    description = "[* PseudoSigner 0.2 [Yoda's Protector 1.02] --> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { E8 03 00 00 00 EB 01 90 90 }

  condition:
    $a
}