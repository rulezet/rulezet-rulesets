rule TTP_XOR_QUAD_CurrentVersionRun_65f0 {
  strings:
    $key_65f0 = { 36 9f [2] 12 91 [2] 39 bd [2] 17 9f [2] 03 84 [2] 0c 9e [2] 12 83 [2] 10 82 [2] 0b 84 [2] 17 83 [2] 0b ac }

  condition:
    any of them
}