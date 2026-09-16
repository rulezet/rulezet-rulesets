rule TTP_XOR_QUAD_CurrentVersionRun_1684 {
  strings:
    $key_1684 = { 45 eb [2] 61 e5 [2] 4a c9 [2] 64 eb [2] 70 f0 [2] 7f ea [2] 61 f7 [2] 63 f6 [2] 78 f0 [2] 64 f7 [2] 78 d8 }

  condition:
    any of them
}