rule TTP_XOR_QUAD_CurrentVersionRun_62ed {
  strings:
    $key_62ed = { 31 82 [2] 15 8c [2] 3e a0 [2] 10 82 [2] 04 99 [2] 0b 83 [2] 15 9e [2] 17 9f [2] 0c 99 [2] 10 9e [2] 0c b1 }

  condition:
    any of them
}