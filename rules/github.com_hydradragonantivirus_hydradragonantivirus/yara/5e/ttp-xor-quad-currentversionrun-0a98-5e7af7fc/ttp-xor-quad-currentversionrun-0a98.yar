rule TTP_XOR_QUAD_CurrentVersionRun_0a98 {
  strings:
    $key_0a98 = { 59 f7 [2] 7d f9 [2] 56 d5 [2] 78 f7 [2] 6c ec [2] 63 f6 [2] 7d eb [2] 7f ea [2] 64 ec [2] 78 eb [2] 64 c4 }

  condition:
    any of them
}