rule TTP_XOR_QUAD_CurrentVersionRun_d9da {
  strings:
    $key_d9da = { 8a b5 [2] ae bb [2] 85 97 [2] ab b5 [2] bf ae [2] b0 b4 [2] ae a9 [2] ac a8 [2] b7 ae [2] ab a9 [2] b7 86 }

  condition:
    any of them
}