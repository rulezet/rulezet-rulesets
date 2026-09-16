rule TTP_XOR_QUAD_CurrentVersionRun_ebf0 {
  strings:
    $key_ebf0 = { b8 9f [2] 9c 91 [2] b7 bd [2] 99 9f [2] 8d 84 [2] 82 9e [2] 9c 83 [2] 9e 82 [2] 85 84 [2] 99 83 [2] 85 ac }

  condition:
    any of them
}