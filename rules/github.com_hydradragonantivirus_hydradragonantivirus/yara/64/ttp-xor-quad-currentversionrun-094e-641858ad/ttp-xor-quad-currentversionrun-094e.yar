rule TTP_XOR_QUAD_CurrentVersionRun_094e {
  strings:
    $key_094e = { 5a 21 [2] 7e 2f [2] 55 03 [2] 7b 21 [2] 6f 3a [2] 60 20 [2] 7e 3d [2] 7c 3c [2] 67 3a [2] 7b 3d [2] 67 12 }

  condition:
    any of them
}