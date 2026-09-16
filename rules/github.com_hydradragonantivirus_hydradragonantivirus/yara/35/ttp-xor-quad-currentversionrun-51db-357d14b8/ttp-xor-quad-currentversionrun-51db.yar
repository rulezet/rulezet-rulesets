rule TTP_XOR_QUAD_CurrentVersionRun_51db {
  strings:
    $key_51db = { 02 b4 [2] 26 ba [2] 0d 96 [2] 23 b4 [2] 37 af [2] 38 b5 [2] 26 a8 [2] 24 a9 [2] 3f af [2] 23 a8 [2] 3f 87 }

  condition:
    any of them
}