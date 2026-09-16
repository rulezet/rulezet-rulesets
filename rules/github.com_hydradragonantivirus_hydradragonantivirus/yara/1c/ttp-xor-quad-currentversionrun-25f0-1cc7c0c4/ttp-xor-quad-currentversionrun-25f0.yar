rule TTP_XOR_QUAD_CurrentVersionRun_25f0 {
  strings:
    $key_25f0 = { 76 9f [2] 52 91 [2] 79 bd [2] 57 9f [2] 43 84 [2] 4c 9e [2] 52 83 [2] 50 82 [2] 4b 84 [2] 57 83 [2] 4b ac }

  condition:
    any of them
}