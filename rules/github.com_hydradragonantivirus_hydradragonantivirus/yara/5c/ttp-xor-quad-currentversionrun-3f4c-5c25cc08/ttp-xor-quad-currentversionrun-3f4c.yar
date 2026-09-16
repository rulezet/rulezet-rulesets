rule TTP_XOR_QUAD_CurrentVersionRun_3f4c {
  strings:
    $key_3f4c = { 6c 23 [2] 48 2d [2] 63 01 [2] 4d 23 [2] 59 38 [2] 56 22 [2] 48 3f [2] 4a 3e [2] 51 38 [2] 4d 3f [2] 51 10 }

  condition:
    any of them
}