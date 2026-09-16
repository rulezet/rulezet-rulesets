rule TTP_XOR_QUAD_CurrentVersionRun_0d4c {
  strings:
    $key_0d4c = { 5e 23 [2] 7a 2d [2] 51 01 [2] 7f 23 [2] 6b 38 [2] 64 22 [2] 7a 3f [2] 78 3e [2] 63 38 [2] 7f 3f [2] 63 10 }

  condition:
    any of them
}