rule TTP_XOR_QUAD_CurrentVersionRun_e24e {
  strings:
    $key_e24e = { b1 21 [2] 95 2f [2] be 03 [2] 90 21 [2] 84 3a [2] 8b 20 [2] 95 3d [2] 97 3c [2] 8c 3a [2] 90 3d [2] 8c 12 }

  condition:
    any of them
}