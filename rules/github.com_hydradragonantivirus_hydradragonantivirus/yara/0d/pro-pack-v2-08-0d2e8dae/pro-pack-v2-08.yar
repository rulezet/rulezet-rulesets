import "pe"
rule PRO_PACK_v2_08 {
  strings:
    $a0 = { 8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53 }

  condition:
    $a0 at pe.entry_point
}