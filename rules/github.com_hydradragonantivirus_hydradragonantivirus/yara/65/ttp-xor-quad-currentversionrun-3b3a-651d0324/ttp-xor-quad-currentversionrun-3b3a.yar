rule TTP_XOR_QUAD_CurrentVersionRun_3b3a {
  strings:
    $key_3b3a = { 68 55 [2] 4c 5b [2] 67 77 [2] 49 55 [2] 5d 4e [2] 52 54 [2] 4c 49 [2] 4e 48 [2] 55 4e [2] 49 49 [2] 55 66 }

  condition:
    any of them
}