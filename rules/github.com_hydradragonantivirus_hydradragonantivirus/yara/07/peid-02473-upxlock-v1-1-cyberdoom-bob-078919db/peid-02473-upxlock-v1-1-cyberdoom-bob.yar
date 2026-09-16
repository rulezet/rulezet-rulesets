rule PEiD_02473_UPXLock_v1_1____CyberDoom___Bob_ {
  meta:
    description = "[UPXLock v1.1 -> CyberDoom & Bob]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? 00 60 }

  condition:
    $a
}