rule TTP_XOR_QUAD_CurrentVersionRun_033a {
  strings:
    $key_033a = { 50 55 [2] 74 5b [2] 5f 77 [2] 71 55 [2] 65 4e [2] 6a 54 [2] 74 49 [2] 76 48 [2] 6d 4e [2] 71 49 [2] 6d 66 }

  condition:
    any of them
}