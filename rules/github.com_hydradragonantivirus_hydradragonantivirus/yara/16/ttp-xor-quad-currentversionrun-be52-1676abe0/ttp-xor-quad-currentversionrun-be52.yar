rule TTP_XOR_QUAD_CurrentVersionRun_be52 {
  strings:
    $key_be52 = { ed 3d [2] c9 33 [2] e2 1f [2] cc 3d [2] d8 26 [2] d7 3c [2] c9 21 [2] cb 20 [2] d0 26 [2] cc 21 [2] d0 0e }

  condition:
    any of them
}