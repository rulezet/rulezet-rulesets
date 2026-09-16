rule TTP_XOR_QUAD_CurrentVersionRun_fbdb {
  strings:
    $key_fbdb = { a8 b4 [2] 8c ba [2] a7 96 [2] 89 b4 [2] 9d af [2] 92 b5 [2] 8c a8 [2] 8e a9 [2] 95 af [2] 89 a8 [2] 95 87 }

  condition:
    any of them
}