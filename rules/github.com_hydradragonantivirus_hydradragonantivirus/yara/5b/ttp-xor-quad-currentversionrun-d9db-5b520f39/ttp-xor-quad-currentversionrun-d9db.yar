rule TTP_XOR_QUAD_CurrentVersionRun_d9db {
  strings:
    $key_d9db = { 8a b4 [2] ae ba [2] 85 96 [2] ab b4 [2] bf af [2] b0 b5 [2] ae a8 [2] ac a9 [2] b7 af [2] ab a8 [2] b7 87 }

  condition:
    any of them
}