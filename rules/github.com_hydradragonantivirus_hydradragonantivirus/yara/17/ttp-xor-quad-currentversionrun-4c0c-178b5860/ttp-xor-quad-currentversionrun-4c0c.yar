rule TTP_XOR_QUAD_CurrentVersionRun_4c0c {
  strings:
    $key_4c0c = { 1f 63 [2] 3b 6d [2] 10 41 [2] 3e 63 [2] 2a 78 [2] 25 62 [2] 3b 7f [2] 39 7e [2] 22 78 [2] 3e 7f [2] 22 50 }

  condition:
    any of them
}