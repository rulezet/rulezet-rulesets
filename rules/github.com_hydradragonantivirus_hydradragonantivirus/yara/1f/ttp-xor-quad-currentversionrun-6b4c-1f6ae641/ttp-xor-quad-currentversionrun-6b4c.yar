rule TTP_XOR_QUAD_CurrentVersionRun_6b4c {
  strings:
    $key_6b4c = { 38 23 [2] 1c 2d [2] 37 01 [2] 19 23 [2] 0d 38 [2] 02 22 [2] 1c 3f [2] 1e 3e [2] 05 38 [2] 19 3f [2] 05 10 }

  condition:
    any of them
}