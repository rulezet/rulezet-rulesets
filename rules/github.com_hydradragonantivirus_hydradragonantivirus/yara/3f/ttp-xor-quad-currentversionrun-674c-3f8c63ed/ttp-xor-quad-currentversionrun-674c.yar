rule TTP_XOR_QUAD_CurrentVersionRun_674c {
  strings:
    $key_674c = { 34 23 [2] 10 2d [2] 3b 01 [2] 15 23 [2] 01 38 [2] 0e 22 [2] 10 3f [2] 12 3e [2] 09 38 [2] 15 3f [2] 09 10 }

  condition:
    any of them
}