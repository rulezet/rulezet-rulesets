rule TTP_XOR_QUAD_CurrentVersionRun_4c6d {
  strings:
    $key_4c6d = { 1f 02 [2] 3b 0c [2] 10 20 [2] 3e 02 [2] 2a 19 [2] 25 03 [2] 3b 1e [2] 39 1f [2] 22 19 [2] 3e 1e [2] 22 31 }

  condition:
    any of them
}