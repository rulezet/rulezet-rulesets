rule TTP_XOR_QUAD_CurrentVersionRun_6ff0 {
  strings:
    $key_6ff0 = { 3c 9f [2] 18 91 [2] 33 bd [2] 1d 9f [2] 09 84 [2] 06 9e [2] 18 83 [2] 1a 82 [2] 01 84 [2] 1d 83 [2] 01 ac }

  condition:
    any of them
}