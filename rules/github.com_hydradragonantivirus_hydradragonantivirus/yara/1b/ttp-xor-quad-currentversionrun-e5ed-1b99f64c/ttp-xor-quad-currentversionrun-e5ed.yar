rule TTP_XOR_QUAD_CurrentVersionRun_e5ed {
  strings:
    $key_e5ed = { b6 82 [2] 92 8c [2] b9 a0 [2] 97 82 [2] 83 99 [2] 8c 83 [2] 92 9e [2] 90 9f [2] 8b 99 [2] 97 9e [2] 8b b1 }

  condition:
    any of them
}