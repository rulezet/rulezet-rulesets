rule TTP_XOR_QUAD_CurrentVersionRun_eb1a {
  strings:
    $key_eb1a = { b8 75 [2] 9c 7b [2] b7 57 [2] 99 75 [2] 8d 6e [2] 82 74 [2] 9c 69 [2] 9e 68 [2] 85 6e [2] 99 69 [2] 85 46 }

  condition:
    any of them
}