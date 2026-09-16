rule TTP_XOR_QUAD_CurrentVersionRun_e9f0 {
  strings:
    $key_e9f0 = { ba 9f [2] 9e 91 [2] b5 bd [2] 9b 9f [2] 8f 84 [2] 80 9e [2] 9e 83 [2] 9c 82 [2] 87 84 [2] 9b 83 [2] 87 ac }

  condition:
    any of them
}