rule TTP_XOR_QUAD_CurrentVersionRun_0d7b {
  strings:
    $key_0d7b = { 5e 14 [2] 7a 1a [2] 51 36 [2] 7f 14 [2] 6b 0f [2] 64 15 [2] 7a 08 [2] 78 09 [2] 63 0f [2] 7f 08 [2] 63 27 }

  condition:
    any of them
}