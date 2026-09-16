rule TTP_XOR_QUAD_CurrentVersionRun_490c {
  strings:
    $key_490c = { 1a 63 [2] 3e 6d [2] 15 41 [2] 3b 63 [2] 2f 78 [2] 20 62 [2] 3e 7f [2] 3c 7e [2] 27 78 [2] 3b 7f [2] 27 50 }

  condition:
    any of them
}