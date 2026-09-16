rule TTP_XOR_QUAD_CurrentVersionRun_28ed {
  strings:
    $key_28ed = { 7b 82 [2] 5f 8c [2] 74 a0 [2] 5a 82 [2] 4e 99 [2] 41 83 [2] 5f 9e [2] 5d 9f [2] 46 99 [2] 5a 9e [2] 46 b1 }

  condition:
    any of them
}