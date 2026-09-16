rule TTP_XOR_QUAD_CurrentVersionRun_02ed {
  strings:
    $key_02ed = { 51 82 [2] 75 8c [2] 5e a0 [2] 70 82 [2] 64 99 [2] 6b 83 [2] 75 9e [2] 77 9f [2] 6c 99 [2] 70 9e [2] 6c b1 }

  condition:
    any of them
}