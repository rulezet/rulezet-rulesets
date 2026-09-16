rule TTP_XOR_QUAD_CurrentVersionRun_577b {
  strings:
    $key_577b = { 04 14 [2] 20 1a [2] 0b 36 [2] 25 14 [2] 31 0f [2] 3e 15 [2] 20 08 [2] 22 09 [2] 39 0f [2] 25 08 [2] 39 27 }

  condition:
    any of them
}