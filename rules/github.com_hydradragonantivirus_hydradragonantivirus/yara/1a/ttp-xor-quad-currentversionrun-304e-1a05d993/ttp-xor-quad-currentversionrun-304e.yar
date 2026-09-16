rule TTP_XOR_QUAD_CurrentVersionRun_304e {
  strings:
    $key_304e = { 63 21 [2] 47 2f [2] 6c 03 [2] 42 21 [2] 56 3a [2] 59 20 [2] 47 3d [2] 45 3c [2] 5e 3a [2] 42 3d [2] 5e 12 }

  condition:
    any of them
}