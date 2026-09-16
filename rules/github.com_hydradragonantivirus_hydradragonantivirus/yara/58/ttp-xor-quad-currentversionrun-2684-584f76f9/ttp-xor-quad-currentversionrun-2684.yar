rule TTP_XOR_QUAD_CurrentVersionRun_2684 {
  strings:
    $key_2684 = { 75 eb [2] 51 e5 [2] 7a c9 [2] 54 eb [2] 40 f0 [2] 4f ea [2] 51 f7 [2] 53 f6 [2] 48 f0 [2] 54 f7 [2] 48 d8 }

  condition:
    any of them
}