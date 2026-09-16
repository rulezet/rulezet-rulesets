rule PEiD_00907_iLUCRYPT_v4_018__exe_ {
  meta:
    description = "[iLUCRYPT v4.018 [exe]"
    ep_only     = "true"

  strings:
    $a = { 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81 }

  condition:
    $a
}