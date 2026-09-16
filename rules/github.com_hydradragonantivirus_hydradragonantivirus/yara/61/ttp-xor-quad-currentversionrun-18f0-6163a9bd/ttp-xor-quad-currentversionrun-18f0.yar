rule TTP_XOR_QUAD_CurrentVersionRun_18f0 {
  strings:
    $key_18f0 = { 4b 9f [2] 6f 91 [2] 44 bd [2] 6a 9f [2] 7e 84 [2] 71 9e [2] 6f 83 [2] 6d 82 [2] 76 84 [2] 6a 83 [2] 76 ac }

  condition:
    any of them
}