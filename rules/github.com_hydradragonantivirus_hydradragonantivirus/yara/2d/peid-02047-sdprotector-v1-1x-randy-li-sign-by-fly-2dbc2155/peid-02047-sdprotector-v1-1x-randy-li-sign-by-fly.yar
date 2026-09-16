rule PEiD_02047_SDProtector_V1_1X____Randy_Li___Sign_by_fly_ {
  meta:
    description = "[SDProtector V1.1X -> Randy Li ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 }

  condition:
    $a
}