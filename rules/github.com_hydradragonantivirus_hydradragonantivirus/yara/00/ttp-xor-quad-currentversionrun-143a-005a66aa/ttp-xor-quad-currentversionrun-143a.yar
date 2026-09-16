rule TTP_XOR_QUAD_CurrentVersionRun_143a {
  strings:
    $key_143a = { 47 55 [2] 63 5b [2] 48 77 [2] 66 55 [2] 72 4e [2] 7d 54 [2] 63 49 [2] 61 48 [2] 7a 4e [2] 66 49 [2] 7a 66 }

  condition:
    any of them
}