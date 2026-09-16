rule TTP_XOR_QUAD_CurrentVersionRun_506d {
  strings:
    $key_506d = { 03 02 [2] 27 0c [2] 0c 20 [2] 22 02 [2] 36 19 [2] 39 03 [2] 27 1e [2] 25 1f [2] 3e 19 [2] 22 1e [2] 3e 31 }

  condition:
    any of them
}