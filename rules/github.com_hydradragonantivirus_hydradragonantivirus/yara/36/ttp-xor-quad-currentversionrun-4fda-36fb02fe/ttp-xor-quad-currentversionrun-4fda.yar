rule TTP_XOR_QUAD_CurrentVersionRun_4fda {
  strings:
    $key_4fda = { 1c b5 [2] 38 bb [2] 13 97 [2] 3d b5 [2] 29 ae [2] 26 b4 [2] 38 a9 [2] 3a a8 [2] 21 ae [2] 3d a9 [2] 21 86 }

  condition:
    any of them
}