rule TTP_XOR_QUAD_CurrentVersionRun_542e {
  strings:
    $key_542e = { 07 41 [2] 23 4f [2] 08 63 [2] 26 41 [2] 32 5a [2] 3d 40 [2] 23 5d [2] 21 5c [2] 3a 5a [2] 26 5d [2] 3a 72 }

  condition:
    any of them
}