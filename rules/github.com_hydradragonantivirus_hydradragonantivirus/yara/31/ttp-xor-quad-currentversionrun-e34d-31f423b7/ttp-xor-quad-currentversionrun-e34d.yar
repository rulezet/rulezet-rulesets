rule TTP_XOR_QUAD_CurrentVersionRun_e34d {
  strings:
    $key_e34d = { b0 22 [2] 94 2c [2] bf 00 [2] 91 22 [2] 85 39 [2] 8a 23 [2] 94 3e [2] 96 3f [2] 8d 39 [2] 91 3e [2] 8d 11 }

  condition:
    any of them
}