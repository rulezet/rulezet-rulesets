rule TTP_XOR_QUAD_CurrentVersionRun_30ed {
  strings:
    $key_30ed = { 63 82 [2] 47 8c [2] 6c a0 [2] 42 82 [2] 56 99 [2] 59 83 [2] 47 9e [2] 45 9f [2] 5e 99 [2] 42 9e [2] 5e b1 }

  condition:
    any of them
}