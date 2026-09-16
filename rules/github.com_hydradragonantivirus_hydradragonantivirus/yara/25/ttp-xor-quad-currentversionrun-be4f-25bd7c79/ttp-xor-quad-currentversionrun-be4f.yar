rule TTP_XOR_QUAD_CurrentVersionRun_be4f {
  strings:
    $key_be4f = { ed 20 [2] c9 2e [2] e2 02 [2] cc 20 [2] d8 3b [2] d7 21 [2] c9 3c [2] cb 3d [2] d0 3b [2] cc 3c [2] d0 13 }

  condition:
    any of them
}