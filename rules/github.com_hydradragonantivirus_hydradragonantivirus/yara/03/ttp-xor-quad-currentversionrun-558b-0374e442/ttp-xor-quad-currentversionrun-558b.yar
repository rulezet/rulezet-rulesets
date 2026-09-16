rule TTP_XOR_QUAD_CurrentVersionRun_558b {
  strings:
    $key_558b = { 06 e4 [2] 22 ea [2] 09 c6 [2] 27 e4 [2] 33 ff [2] 3c e5 [2] 22 f8 [2] 20 f9 [2] 3b ff [2] 27 f8 [2] 3b d7 }

  condition:
    any of them
}