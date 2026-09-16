rule TTP_XOR_QUAD_CurrentVersionRun_eb7a {
  strings:
    $key_eb7a = { b8 15 [2] 9c 1b [2] b7 37 [2] 99 15 [2] 8d 0e [2] 82 14 [2] 9c 09 [2] 9e 08 [2] 85 0e [2] 99 09 [2] 85 26 }

  condition:
    any of them
}