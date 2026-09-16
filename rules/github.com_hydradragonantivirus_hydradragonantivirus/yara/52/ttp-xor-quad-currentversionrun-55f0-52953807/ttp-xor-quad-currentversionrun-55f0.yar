rule TTP_XOR_QUAD_CurrentVersionRun_55f0 {
  strings:
    $key_55f0 = { 06 9f [2] 22 91 [2] 09 bd [2] 27 9f [2] 33 84 [2] 3c 9e [2] 22 83 [2] 20 82 [2] 3b 84 [2] 27 83 [2] 3b ac }

  condition:
    any of them
}