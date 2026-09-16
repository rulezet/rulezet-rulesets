rule TTP_XOR_QUAD_CurrentVersionRun_66f6 {
  strings:
    $key_66f6 = { 35 99 [2] 11 97 [2] 3a bb [2] 14 99 [2] 00 82 [2] 0f 98 [2] 11 85 [2] 13 84 [2] 08 82 [2] 14 85 [2] 08 aa }

  condition:
    any of them
}