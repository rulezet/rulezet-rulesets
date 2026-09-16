rule TTP_XOR_QUAD_CurrentVersionRun_236c {
  strings:
    $key_236c = { 70 03 [2] 54 0d [2] 7f 21 [2] 51 03 [2] 45 18 [2] 4a 02 [2] 54 1f [2] 56 1e [2] 4d 18 [2] 51 1f [2] 4d 30 }

  condition:
    any of them
}