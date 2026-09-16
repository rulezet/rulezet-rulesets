rule TTP_XOR_QUAD_CurrentVersionRun_35ed {
  strings:
    $key_35ed = { 66 82 [2] 42 8c [2] 69 a0 [2] 47 82 [2] 53 99 [2] 5c 83 [2] 42 9e [2] 40 9f [2] 5b 99 [2] 47 9e [2] 5b b1 }

  condition:
    any of them
}