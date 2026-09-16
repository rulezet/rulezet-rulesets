rule TTP_XOR_QUAD_CurrentVersionRun_1f3a {
  strings:
    $key_1f3a = { 4c 55 [2] 68 5b [2] 43 77 [2] 6d 55 [2] 79 4e [2] 76 54 [2] 68 49 [2] 6a 48 [2] 71 4e [2] 6d 49 [2] 71 66 }

  condition:
    any of them
}