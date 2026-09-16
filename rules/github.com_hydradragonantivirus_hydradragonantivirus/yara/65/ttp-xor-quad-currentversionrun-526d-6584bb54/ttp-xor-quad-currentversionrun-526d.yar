rule TTP_XOR_QUAD_CurrentVersionRun_526d {
  strings:
    $key_526d = { 01 02 [2] 25 0c [2] 0e 20 [2] 20 02 [2] 34 19 [2] 3b 03 [2] 25 1e [2] 27 1f [2] 3c 19 [2] 20 1e [2] 3c 31 }

  condition:
    any of them
}