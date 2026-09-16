rule TTP_XOR_QUAD_CurrentVersionRun_00da {
  strings:
    $key_00da = { 53 b5 [2] 77 bb [2] 5c 97 [2] 72 b5 [2] 66 ae [2] 69 b4 [2] 77 a9 [2] 75 a8 [2] 6e ae [2] 72 a9 [2] 6e 86 }

  condition:
    any of them
}