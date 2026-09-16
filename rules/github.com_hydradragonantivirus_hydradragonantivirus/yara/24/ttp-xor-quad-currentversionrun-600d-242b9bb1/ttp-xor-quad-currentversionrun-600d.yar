rule TTP_XOR_QUAD_CurrentVersionRun_600d {
  strings:
    $key_600d = { 33 62 [2] 17 6c [2] 3c 40 [2] 12 62 [2] 06 79 [2] 09 63 [2] 17 7e [2] 15 7f [2] 0e 79 [2] 12 7e [2] 0e 51 }

  condition:
    any of them
}