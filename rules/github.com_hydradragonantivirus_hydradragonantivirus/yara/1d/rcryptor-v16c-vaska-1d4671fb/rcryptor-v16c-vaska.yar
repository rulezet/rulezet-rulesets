import "pe"
rule _RCryptor_v16c__Vaska_ {
  meta:
    description = "RCryptor v1.6c --> Vaska"

  strings:
    $0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB }

  condition:
    $0 at pe.entry_point
}