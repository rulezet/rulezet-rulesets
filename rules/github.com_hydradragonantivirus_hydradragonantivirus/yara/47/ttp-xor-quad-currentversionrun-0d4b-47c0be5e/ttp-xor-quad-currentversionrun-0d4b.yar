rule TTP_XOR_QUAD_CurrentVersionRun_0d4b {
  strings:
    $key_0d4b = { 5e 24 [2] 7a 2a [2] 51 06 [2] 7f 24 [2] 6b 3f [2] 64 25 [2] 7a 38 [2] 78 39 [2] 63 3f [2] 7f 38 [2] 63 17 }

  condition:
    any of them
}