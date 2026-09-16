rule TTP_XOR_QUAD_CurrentVersionRun_0d77 {
  strings:
    $key_0d77 = { 5e 18 [2] 7a 16 [2] 51 3a [2] 7f 18 [2] 6b 03 [2] 64 19 [2] 7a 04 [2] 78 05 [2] 63 03 [2] 7f 04 [2] 63 2b }

  condition:
    any of them
}