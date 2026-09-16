rule TTP_XOR_QUAD_CurrentVersionRun_4910 {
  strings:
    $key_4910 = { 1a 7f [2] 3e 71 [2] 15 5d [2] 3b 7f [2] 2f 64 [2] 20 7e [2] 3e 63 [2] 3c 62 [2] 27 64 [2] 3b 63 [2] 27 4c }

  condition:
    any of them
}