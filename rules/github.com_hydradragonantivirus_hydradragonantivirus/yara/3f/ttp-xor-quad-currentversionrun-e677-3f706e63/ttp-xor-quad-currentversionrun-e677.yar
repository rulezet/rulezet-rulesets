rule TTP_XOR_QUAD_CurrentVersionRun_e677 {
  strings:
    $key_e677 = { b5 18 [2] 91 16 [2] ba 3a [2] 94 18 [2] 80 03 [2] 8f 19 [2] 91 04 [2] 93 05 [2] 88 03 [2] 94 04 [2] 88 2b }

  condition:
    any of them
}