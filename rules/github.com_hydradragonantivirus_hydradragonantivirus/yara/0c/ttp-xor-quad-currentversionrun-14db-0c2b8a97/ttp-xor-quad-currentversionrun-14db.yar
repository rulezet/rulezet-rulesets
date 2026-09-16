rule TTP_XOR_QUAD_CurrentVersionRun_14db {
  strings:
    $key_14db = { 47 b4 [2] 63 ba [2] 48 96 [2] 66 b4 [2] 72 af [2] 7d b5 [2] 63 a8 [2] 61 a9 [2] 7a af [2] 66 a8 [2] 7a 87 }

  condition:
    any of them
}