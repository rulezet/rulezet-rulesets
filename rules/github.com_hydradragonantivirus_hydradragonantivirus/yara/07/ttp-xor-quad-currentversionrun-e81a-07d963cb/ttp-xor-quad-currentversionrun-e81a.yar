rule TTP_XOR_QUAD_CurrentVersionRun_e81a {
  strings:
    $key_e81a = { bb 75 [2] 9f 7b [2] b4 57 [2] 9a 75 [2] 8e 6e [2] 81 74 [2] 9f 69 [2] 9d 68 [2] 86 6e [2] 9a 69 [2] 86 46 }

  condition:
    any of them
}