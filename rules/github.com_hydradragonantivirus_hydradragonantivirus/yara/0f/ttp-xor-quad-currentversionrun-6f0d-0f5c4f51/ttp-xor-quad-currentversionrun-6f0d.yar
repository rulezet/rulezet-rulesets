rule TTP_XOR_QUAD_CurrentVersionRun_6f0d {
  strings:
    $key_6f0d = { 3c 62 [2] 18 6c [2] 33 40 [2] 1d 62 [2] 09 79 [2] 06 63 [2] 18 7e [2] 1a 7f [2] 01 79 [2] 1d 7e [2] 01 51 }

  condition:
    any of them
}