rule TTP_XOR_QUAD_CurrentVersionRun_184c {
  strings:
    $key_184c = { 4b 23 [2] 6f 2d [2] 44 01 [2] 6a 23 [2] 7e 38 [2] 71 22 [2] 6f 3f [2] 6d 3e [2] 76 38 [2] 6a 3f [2] 76 10 }

  condition:
    any of them
}