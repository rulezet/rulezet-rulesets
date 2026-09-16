rule TTP_XOR_QUAD_CurrentVersionRun_331a {
  strings:
    $key_331a = { 60 75 [2] 44 7b [2] 6f 57 [2] 41 75 [2] 55 6e [2] 5a 74 [2] 44 69 [2] 46 68 [2] 5d 6e [2] 41 69 [2] 5d 46 }

  condition:
    any of them
}