rule PEiD_01966_RLP_V0_7_3_beta____ap0x___Sign_by_fly_ {
  meta:
    description = "[RLP V0.7.3.beta -> ap0x ! Sign by fly]"
    ep_only     = "false"

  strings:
    $a = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }

  condition:
    $a
}