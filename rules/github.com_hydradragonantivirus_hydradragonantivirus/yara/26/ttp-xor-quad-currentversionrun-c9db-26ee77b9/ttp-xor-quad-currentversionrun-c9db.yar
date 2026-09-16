rule TTP_XOR_QUAD_CurrentVersionRun_c9db {
  strings:
    $key_c9db = { 9a b4 [2] be ba [2] 95 96 [2] bb b4 [2] af af [2] a0 b5 [2] be a8 [2] bc a9 [2] a7 af [2] bb a8 [2] a7 87 }

  condition:
    any of them
}