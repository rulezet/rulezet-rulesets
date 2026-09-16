rule TTP_XOR_QUAD_CurrentVersionRun_34da {
  strings:
    $key_34da = { 67 b5 [2] 43 bb [2] 68 97 [2] 46 b5 [2] 52 ae [2] 5d b4 [2] 43 a9 [2] 41 a8 [2] 5a ae [2] 46 a9 [2] 5a 86 }

  condition:
    any of them
}