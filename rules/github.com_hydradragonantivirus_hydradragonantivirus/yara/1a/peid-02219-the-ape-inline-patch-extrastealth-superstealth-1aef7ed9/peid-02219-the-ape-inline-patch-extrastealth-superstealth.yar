rule PEiD_02219_The_aPE_Inline_Patch_ExtraStealth__SuperStealth__ {
  meta:
    description = "[The aPE Inline Patch ExtraStealth, SuperStealth)]"
    ep_only     = "true"

  strings:
    $a = { E8 02 ?? ?? ?? EB 01 C3 3E 8B 44 24 FC 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 }

  condition:
    $a
}