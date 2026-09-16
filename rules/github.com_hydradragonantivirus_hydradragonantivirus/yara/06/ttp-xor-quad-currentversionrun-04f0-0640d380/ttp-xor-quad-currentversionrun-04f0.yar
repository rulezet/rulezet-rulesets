rule TTP_XOR_QUAD_CurrentVersionRun_04f0 {
  strings:
    $key_04f0 = { 57 9f [2] 73 91 [2] 58 bd [2] 76 9f [2] 62 84 [2] 6d 9e [2] 73 83 [2] 71 82 [2] 6a 84 [2] 76 83 [2] 6a ac }

  condition:
    any of them
}