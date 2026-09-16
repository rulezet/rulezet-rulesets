rule TTP_XOR_QUAD_CurrentVersionRun_d198 {
  strings:
    $key_d198 = { 82 f7 [2] a6 f9 [2] 8d d5 [2] a3 f7 [2] b7 ec [2] b8 f6 [2] a6 eb [2] a4 ea [2] bf ec [2] a3 eb [2] bf c4 }

  condition:
    any of them
}