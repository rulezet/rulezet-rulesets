rule TTP_XOR_QUAD_CurrentVersionRun_e9db {
  strings:
    $key_e9db = { ba b4 [2] 9e ba [2] b5 96 [2] 9b b4 [2] 8f af [2] 80 b5 [2] 9e a8 [2] 9c a9 [2] 87 af [2] 9b a8 [2] 87 87 }

  condition:
    any of them
}