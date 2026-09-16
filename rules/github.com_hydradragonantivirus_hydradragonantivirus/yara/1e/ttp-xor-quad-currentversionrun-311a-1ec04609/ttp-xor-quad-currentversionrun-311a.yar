rule TTP_XOR_QUAD_CurrentVersionRun_311a {
  strings:
    $key_311a = { 62 75 [2] 46 7b [2] 6d 57 [2] 43 75 [2] 57 6e [2] 58 74 [2] 46 69 [2] 44 68 [2] 5f 6e [2] 43 69 [2] 5f 46 }

  condition:
    any of them
}