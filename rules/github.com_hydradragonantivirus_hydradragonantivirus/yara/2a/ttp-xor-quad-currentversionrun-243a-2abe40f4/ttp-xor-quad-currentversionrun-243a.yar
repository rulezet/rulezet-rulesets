rule TTP_XOR_QUAD_CurrentVersionRun_243a {
  strings:
    $key_243a = { 77 55 [2] 53 5b [2] 78 77 [2] 56 55 [2] 42 4e [2] 4d 54 [2] 53 49 [2] 51 48 [2] 4a 4e [2] 56 49 [2] 4a 66 }

  condition:
    any of them
}