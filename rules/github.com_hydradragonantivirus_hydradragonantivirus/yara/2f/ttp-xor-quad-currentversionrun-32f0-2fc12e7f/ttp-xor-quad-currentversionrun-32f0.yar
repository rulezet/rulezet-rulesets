rule TTP_XOR_QUAD_CurrentVersionRun_32f0 {
  strings:
    $key_32f0 = { 61 9f [2] 45 91 [2] 6e bd [2] 40 9f [2] 54 84 [2] 5b 9e [2] 45 83 [2] 47 82 [2] 5c 84 [2] 40 83 [2] 5c ac }

  condition:
    any of them
}