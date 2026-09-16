rule TTP_XOR_QUAD_CurrentVersionRun_54f0 {
  strings:
    $key_54f0 = { 07 9f [2] 23 91 [2] 08 bd [2] 26 9f [2] 32 84 [2] 3d 9e [2] 23 83 [2] 21 82 [2] 3a 84 [2] 26 83 [2] 3a ac }

  condition:
    any of them
}