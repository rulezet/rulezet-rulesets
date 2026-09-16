rule TTP_XOR_QUAD_CurrentVersionRun_34ed {
  strings:
    $key_34ed = { 67 82 [2] 43 8c [2] 68 a0 [2] 46 82 [2] 52 99 [2] 5d 83 [2] 43 9e [2] 41 9f [2] 5a 99 [2] 46 9e [2] 5a b1 }

  condition:
    any of them
}