rule TTP_XOR_QUAD_CurrentVersionRun_096f {
  strings:
    $key_096f = { 5a 00 [2] 7e 0e [2] 55 22 [2] 7b 00 [2] 6f 1b [2] 60 01 [2] 7e 1c [2] 7c 1d [2] 67 1b [2] 7b 1c [2] 67 33 }

  condition:
    any of them
}