rule TTP_XOR_QUAD_CurrentVersionRun_e8f0 {
  strings:
    $key_e8f0 = { bb 9f [2] 9f 91 [2] b4 bd [2] 9a 9f [2] 8e 84 [2] 81 9e [2] 9f 83 [2] 9d 82 [2] 86 84 [2] 9a 83 [2] 86 ac }

  condition:
    any of them
}