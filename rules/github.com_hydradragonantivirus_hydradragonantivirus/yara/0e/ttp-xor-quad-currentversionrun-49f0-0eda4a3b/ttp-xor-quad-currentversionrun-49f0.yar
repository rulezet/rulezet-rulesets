rule TTP_XOR_QUAD_CurrentVersionRun_49f0 {
  strings:
    $key_49f0 = { 1a 9f [2] 3e 91 [2] 15 bd [2] 3b 9f [2] 2f 84 [2] 20 9e [2] 3e 83 [2] 3c 82 [2] 27 84 [2] 3b 83 [2] 27 ac }

  condition:
    any of them
}