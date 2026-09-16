rule TTP_XOR_QUAD_CurrentVersionRun_6c6c {
  strings:
    $key_6c6c = { 3f 03 [2] 1b 0d [2] 30 21 [2] 1e 03 [2] 0a 18 [2] 05 02 [2] 1b 1f [2] 19 1e [2] 02 18 [2] 1e 1f [2] 02 30 }

  condition:
    any of them
}