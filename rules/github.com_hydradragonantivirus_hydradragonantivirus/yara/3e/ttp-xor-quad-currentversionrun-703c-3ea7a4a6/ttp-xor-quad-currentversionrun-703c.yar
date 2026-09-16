rule TTP_XOR_QUAD_CurrentVersionRun_703c {
  strings:
    $key_703c = { 23 53 [2] 07 5d [2] 2c 71 [2] 02 53 [2] 16 48 [2] 19 52 [2] 07 4f [2] 05 4e [2] 1e 48 [2] 02 4f [2] 1e 60 }

  condition:
    any of them
}