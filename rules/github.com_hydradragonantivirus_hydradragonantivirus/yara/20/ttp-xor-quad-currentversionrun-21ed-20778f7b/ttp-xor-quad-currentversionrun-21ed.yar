rule TTP_XOR_QUAD_CurrentVersionRun_21ed {
  strings:
    $key_21ed = { 72 82 [2] 56 8c [2] 7d a0 [2] 53 82 [2] 47 99 [2] 48 83 [2] 56 9e [2] 54 9f [2] 4f 99 [2] 53 9e [2] 4f b1 }

  condition:
    any of them
}