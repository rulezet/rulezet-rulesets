rule TTP_XOR_QUAD_CurrentVersionRun_116c {
  strings:
    $key_116c = { 42 03 [2] 66 0d [2] 4d 21 [2] 63 03 [2] 77 18 [2] 78 02 [2] 66 1f [2] 64 1e [2] 7f 18 [2] 63 1f [2] 7f 30 }

  condition:
    any of them
}