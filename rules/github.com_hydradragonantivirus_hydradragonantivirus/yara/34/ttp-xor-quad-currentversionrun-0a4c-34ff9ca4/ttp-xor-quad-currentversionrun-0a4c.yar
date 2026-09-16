rule TTP_XOR_QUAD_CurrentVersionRun_0a4c {
  strings:
    $key_0a4c = { 59 23 [2] 7d 2d [2] 56 01 [2] 78 23 [2] 6c 38 [2] 63 22 [2] 7d 3f [2] 7f 3e [2] 64 38 [2] 78 3f [2] 64 10 }

  condition:
    any of them
}