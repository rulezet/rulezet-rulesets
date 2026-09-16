rule TTP_XOR_QUAD_CurrentVersionRun_680d {
  strings:
    $key_680d = { 3b 62 [2] 1f 6c [2] 34 40 [2] 1a 62 [2] 0e 79 [2] 01 63 [2] 1f 7e [2] 1d 7f [2] 06 79 [2] 1a 7e [2] 06 51 }

  condition:
    any of them
}