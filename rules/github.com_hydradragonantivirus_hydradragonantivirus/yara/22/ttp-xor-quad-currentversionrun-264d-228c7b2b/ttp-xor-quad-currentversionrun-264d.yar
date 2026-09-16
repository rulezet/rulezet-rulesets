rule TTP_XOR_QUAD_CurrentVersionRun_264d {
  strings:
    $key_264d = { 75 22 [2] 51 2c [2] 7a 00 [2] 54 22 [2] 40 39 [2] 4f 23 [2] 51 3e [2] 53 3f [2] 48 39 [2] 54 3e [2] 48 11 }

  condition:
    any of them
}