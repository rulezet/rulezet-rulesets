rule TTP_XOR_QUAD_CurrentVersionRun_01da {
  strings:
    $key_01da = { 52 b5 [2] 76 bb [2] 5d 97 [2] 73 b5 [2] 67 ae [2] 68 b4 [2] 76 a9 [2] 74 a8 [2] 6f ae [2] 73 a9 [2] 6f 86 }

  condition:
    any of them
}