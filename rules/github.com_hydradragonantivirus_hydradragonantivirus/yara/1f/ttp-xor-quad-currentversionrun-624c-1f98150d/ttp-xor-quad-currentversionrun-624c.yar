rule TTP_XOR_QUAD_CurrentVersionRun_624c {
  strings:
    $key_624c = { 31 23 [2] 15 2d [2] 3e 01 [2] 10 23 [2] 04 38 [2] 0b 22 [2] 15 3f [2] 17 3e [2] 0c 38 [2] 10 3f [2] 0c 10 }

  condition:
    any of them
}