rule TTP_XOR_QUAD_CurrentVersionRun_0d6b {
  strings:
    $key_0d6b = { 5e 04 [2] 7a 0a [2] 51 26 [2] 7f 04 [2] 6b 1f [2] 64 05 [2] 7a 18 [2] 78 19 [2] 63 1f [2] 7f 18 [2] 63 37 }

  condition:
    any of them
}