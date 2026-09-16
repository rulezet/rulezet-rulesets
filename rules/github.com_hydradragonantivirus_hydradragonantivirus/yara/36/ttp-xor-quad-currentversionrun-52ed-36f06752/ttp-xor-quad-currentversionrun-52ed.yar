rule TTP_XOR_QUAD_CurrentVersionRun_52ed {
  strings:
    $key_52ed = { 01 82 [2] 25 8c [2] 0e a0 [2] 20 82 [2] 34 99 [2] 3b 83 [2] 25 9e [2] 27 9f [2] 3c 99 [2] 20 9e [2] 3c b1 }

  condition:
    any of them
}