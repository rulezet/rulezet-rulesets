rule TTP_XOR_QUAD_CurrentVersionRun_7af0 {
  strings:
    $key_7af0 = { 29 9f [2] 0d 91 [2] 26 bd [2] 08 9f [2] 1c 84 [2] 13 9e [2] 0d 83 [2] 0f 82 [2] 14 84 [2] 08 83 [2] 14 ac }

  condition:
    any of them
}