rule TTP_XOR_QUAD_CurrentVersionRun_be3d {
  strings:
    $key_be3d = { ed 52 [2] c9 5c [2] e2 70 [2] cc 52 [2] d8 49 [2] d7 53 [2] c9 4e [2] cb 4f [2] d0 49 [2] cc 4e [2] d0 61 }

  condition:
    any of them
}