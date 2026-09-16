rule PEiD_03502_XCR_v0_12_ {
  meta:
    description = "[XCR v0.12]"
    ep_only     = "true"

  strings:
    $a = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }

  condition:
    $a
}