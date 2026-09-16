rule TTP_XOR_QUAD_CurrentVersionRun_32f1 {
  strings:
    $key_32f1 = { 61 9e [2] 45 90 [2] 6e bc [2] 40 9e [2] 54 85 [2] 5b 9f [2] 45 82 [2] 47 83 [2] 5c 85 [2] 40 82 [2] 5c ad }

  condition:
    any of them
}