rule TTP_XOR_QUAD_CurrentVersionRun_1fda {
  strings:
    $key_1fda = { 4c b5 [2] 68 bb [2] 43 97 [2] 6d b5 [2] 79 ae [2] 76 b4 [2] 68 a9 [2] 6a a8 [2] 71 ae [2] 6d a9 [2] 71 86 }

  condition:
    any of them
}