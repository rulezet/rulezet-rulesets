rule TTP_XOR_QUAD_CurrentVersionRun_44f0 {
  strings:
    $key_44f0 = { 17 9f [2] 33 91 [2] 18 bd [2] 36 9f [2] 22 84 [2] 2d 9e [2] 33 83 [2] 31 82 [2] 2a 84 [2] 36 83 [2] 2a ac }

  condition:
    any of them
}