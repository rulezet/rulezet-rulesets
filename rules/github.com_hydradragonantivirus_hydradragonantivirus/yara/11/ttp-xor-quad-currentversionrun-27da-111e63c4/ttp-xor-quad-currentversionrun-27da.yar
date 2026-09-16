rule TTP_XOR_QUAD_CurrentVersionRun_27da {
  strings:
    $key_27da = { 74 b5 [2] 50 bb [2] 7b 97 [2] 55 b5 [2] 41 ae [2] 4e b4 [2] 50 a9 [2] 52 a8 [2] 49 ae [2] 55 a9 [2] 49 86 }

  condition:
    any of them
}