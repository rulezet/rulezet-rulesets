rule TTP_XOR_QUAD_CurrentVersionRun_b9db {
  strings:
    $key_b9db = { ea b4 [2] ce ba [2] e5 96 [2] cb b4 [2] df af [2] d0 b5 [2] ce a8 [2] cc a9 [2] d7 af [2] cb a8 [2] d7 87 }

  condition:
    any of them
}