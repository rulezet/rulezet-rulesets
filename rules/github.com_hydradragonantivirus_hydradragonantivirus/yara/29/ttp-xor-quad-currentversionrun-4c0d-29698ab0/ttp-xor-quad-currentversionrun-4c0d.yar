rule TTP_XOR_QUAD_CurrentVersionRun_4c0d {
  strings:
    $key_4c0d = { 1f 62 [2] 3b 6c [2] 10 40 [2] 3e 62 [2] 2a 79 [2] 25 63 [2] 3b 7e [2] 39 7f [2] 22 79 [2] 3e 7e [2] 22 51 }

  condition:
    any of them
}