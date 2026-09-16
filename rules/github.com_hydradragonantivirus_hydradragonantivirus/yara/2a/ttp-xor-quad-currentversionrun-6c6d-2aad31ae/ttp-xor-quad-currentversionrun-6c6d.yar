rule TTP_XOR_QUAD_CurrentVersionRun_6c6d {
  strings:
    $key_6c6d = { 3f 02 [2] 1b 0c [2] 30 20 [2] 1e 02 [2] 0a 19 [2] 05 03 [2] 1b 1e [2] 19 1f [2] 02 19 [2] 1e 1e [2] 02 31 }

  condition:
    any of them
}