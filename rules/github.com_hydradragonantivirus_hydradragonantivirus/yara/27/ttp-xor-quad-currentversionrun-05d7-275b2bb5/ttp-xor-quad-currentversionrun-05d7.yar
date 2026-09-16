rule TTP_XOR_QUAD_CurrentVersionRun_05d7 {
  strings:
    $key_05d7 = { 56 b8 [2] 72 b6 [2] 59 9a [2] 77 b8 [2] 63 a3 [2] 6c b9 [2] 72 a4 [2] 70 a5 [2] 6b a3 [2] 77 a4 [2] 6b 8b }

  condition:
    any of them
}