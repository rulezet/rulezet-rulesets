rule TTP_XOR_QUAD_CurrentVersionRun_14ed {
  strings:
    $key_14ed = { 47 82 [2] 63 8c [2] 48 a0 [2] 66 82 [2] 72 99 [2] 7d 83 [2] 63 9e [2] 61 9f [2] 7a 99 [2] 66 9e [2] 7a b1 }

  condition:
    any of them
}