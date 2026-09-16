rule TTP_XOR_QUAD_CurrentVersionRun_0cf0 {
  strings:
    $key_0cf0 = { 5f 9f [2] 7b 91 [2] 50 bd [2] 7e 9f [2] 6a 84 [2] 65 9e [2] 7b 83 [2] 79 82 [2] 62 84 [2] 7e 83 [2] 62 ac }

  condition:
    any of them
}