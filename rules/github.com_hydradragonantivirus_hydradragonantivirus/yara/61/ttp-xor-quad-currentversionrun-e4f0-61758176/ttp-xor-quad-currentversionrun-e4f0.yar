rule TTP_XOR_QUAD_CurrentVersionRun_e4f0 {
  strings:
    $key_e4f0 = { b7 9f [2] 93 91 [2] b8 bd [2] 96 9f [2] 82 84 [2] 8d 9e [2] 93 83 [2] 91 82 [2] 8a 84 [2] 96 83 [2] 8a ac }

  condition:
    any of them
}