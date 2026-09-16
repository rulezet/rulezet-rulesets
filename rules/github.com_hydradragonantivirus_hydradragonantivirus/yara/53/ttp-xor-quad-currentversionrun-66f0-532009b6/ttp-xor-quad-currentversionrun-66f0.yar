rule TTP_XOR_QUAD_CurrentVersionRun_66f0 {
  strings:
    $key_66f0 = { 35 9f [2] 11 91 [2] 3a bd [2] 14 9f [2] 00 84 [2] 0f 9e [2] 11 83 [2] 13 82 [2] 08 84 [2] 14 83 [2] 08 ac }

  condition:
    any of them
}