rule TTP_XOR_QUAD_CurrentVersionRun_f2f0 {
  strings:
    $key_f2f0 = { a1 9f [2] 85 91 [2] ae bd [2] 80 9f [2] 94 84 [2] 9b 9e [2] 85 83 [2] 87 82 [2] 9c 84 [2] 80 83 [2] 9c ac }

  condition:
    any of them
}