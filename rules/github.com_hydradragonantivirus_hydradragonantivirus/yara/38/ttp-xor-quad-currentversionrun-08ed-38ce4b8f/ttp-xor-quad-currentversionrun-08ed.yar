rule TTP_XOR_QUAD_CurrentVersionRun_08ed {
  strings:
    $key_08ed = { 5b 82 [2] 7f 8c [2] 54 a0 [2] 7a 82 [2] 6e 99 [2] 61 83 [2] 7f 9e [2] 7d 9f [2] 66 99 [2] 7a 9e [2] 66 b1 }

  condition:
    any of them
}