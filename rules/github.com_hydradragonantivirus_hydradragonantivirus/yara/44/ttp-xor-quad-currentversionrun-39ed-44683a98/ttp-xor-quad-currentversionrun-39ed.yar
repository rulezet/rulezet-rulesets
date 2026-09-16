rule TTP_XOR_QUAD_CurrentVersionRun_39ed {
  strings:
    $key_39ed = { 6a 82 [2] 4e 8c [2] 65 a0 [2] 4b 82 [2] 5f 99 [2] 50 83 [2] 4e 9e [2] 4c 9f [2] 57 99 [2] 4b 9e [2] 57 b1 }

  condition:
    any of them
}