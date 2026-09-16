rule TTP_XOR_QUAD_CurrentVersionRun_520d {
  strings:
    $key_520d = { 01 62 [2] 25 6c [2] 0e 40 [2] 20 62 [2] 34 79 [2] 3b 63 [2] 25 7e [2] 27 7f [2] 3c 79 [2] 20 7e [2] 3c 51 }

  condition:
    any of them
}