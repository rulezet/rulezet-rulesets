rule TTP_XOR_QUAD_CurrentVersionRun_0d85 {
  strings:
    $key_0d85 = { 5e ea [2] 7a e4 [2] 51 c8 [2] 7f ea [2] 6b f1 [2] 64 eb [2] 7a f6 [2] 78 f7 [2] 63 f1 [2] 7f f6 [2] 63 d9 }

  condition:
    any of them
}