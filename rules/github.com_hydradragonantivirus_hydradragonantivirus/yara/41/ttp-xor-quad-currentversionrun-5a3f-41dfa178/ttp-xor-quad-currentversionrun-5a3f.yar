rule TTP_XOR_QUAD_CurrentVersionRun_5a3f {
  strings:
    $key_5a3f = { 09 50 [2] 2d 5e [2] 06 72 [2] 28 50 [2] 3c 4b [2] 33 51 [2] 2d 4c [2] 2f 4d [2] 34 4b [2] 28 4c [2] 34 63 }

  condition:
    any of them
}