rule TTP_XOR_QUAD_CurrentVersionRun_65ed {
  strings:
    $key_65ed = { 36 82 [2] 12 8c [2] 39 a0 [2] 17 82 [2] 03 99 [2] 0c 83 [2] 12 9e [2] 10 9f [2] 0b 99 [2] 17 9e [2] 0b b1 }

  condition:
    any of them
}