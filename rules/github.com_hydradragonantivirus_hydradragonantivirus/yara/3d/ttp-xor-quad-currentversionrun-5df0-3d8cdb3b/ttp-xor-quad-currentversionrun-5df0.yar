rule TTP_XOR_QUAD_CurrentVersionRun_5df0 {
  strings:
    $key_5df0 = { 0e 9f [2] 2a 91 [2] 01 bd [2] 2f 9f [2] 3b 84 [2] 34 9e [2] 2a 83 [2] 28 82 [2] 33 84 [2] 2f 83 [2] 33 ac }

  condition:
    any of them
}