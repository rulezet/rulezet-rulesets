rule TTP_XOR_QUAD_CurrentVersionRun_77f0 {
  strings:
    $key_77f0 = { 24 9f [2] 00 91 [2] 2b bd [2] 05 9f [2] 11 84 [2] 1e 9e [2] 00 83 [2] 02 82 [2] 19 84 [2] 05 83 [2] 19 ac }

  condition:
    any of them
}