rule TTP_XOR_QUAD_CurrentVersionRun_12f0 {
  strings:
    $key_12f0 = { 41 9f [2] 65 91 [2] 4e bd [2] 60 9f [2] 74 84 [2] 7b 9e [2] 65 83 [2] 67 82 [2] 7c 84 [2] 60 83 [2] 7c ac }

  condition:
    any of them
}