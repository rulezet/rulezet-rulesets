rule TTP_XOR_QUAD_CurrentVersionRun_490d {
  strings:
    $key_490d = { 1a 62 [2] 3e 6c [2] 15 40 [2] 3b 62 [2] 2f 79 [2] 20 63 [2] 3e 7e [2] 3c 7f [2] 27 79 [2] 3b 7e [2] 27 51 }

  condition:
    any of them
}