rule TTP_XOR_QUAD_CurrentVersionRun_503a {
  strings:
    $key_503a = { 03 55 [2] 27 5b [2] 0c 77 [2] 22 55 [2] 36 4e [2] 39 54 [2] 27 49 [2] 25 48 [2] 3e 4e [2] 22 49 [2] 3e 66 }

  condition:
    any of them
}