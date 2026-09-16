rule PEiD_00287_bambam_V0_01____bedrock_ {
  meta:
    description = "[bambam V0.01 -> bedrock]"
    ep_only     = "true"

  strings:
    $a = { 6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF }

  condition:
    $a
}