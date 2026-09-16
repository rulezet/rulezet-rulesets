rule TTP_XOR_QUAD_CurrentVersionRun_75f0 {
  strings:
    $key_75f0 = { 26 9f [2] 02 91 [2] 29 bd [2] 07 9f [2] 13 84 [2] 1c 9e [2] 02 83 [2] 00 82 [2] 1b 84 [2] 07 83 [2] 1b ac }

  condition:
    any of them
}