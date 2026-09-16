rule TTP_XOR_QUAD_CurrentVersionRun_201a {
  strings:
    $key_201a = { 73 75 [2] 57 7b [2] 7c 57 [2] 52 75 [2] 46 6e [2] 49 74 [2] 57 69 [2] 55 68 [2] 4e 6e [2] 52 69 [2] 4e 46 }

  condition:
    any of them
}