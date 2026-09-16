rule TTP_XOR_QUAD_CurrentVersionRun_013a {
  strings:
    $key_013a = { 52 55 [2] 76 5b [2] 5d 77 [2] 73 55 [2] 67 4e [2] 68 54 [2] 76 49 [2] 74 48 [2] 6f 4e [2] 73 49 [2] 6f 66 }

  condition:
    any of them
}