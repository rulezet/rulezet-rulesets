rule TTP_XOR_QUAD_CurrentVersionRun_be4a {
  strings:
    $key_be4a = { ed 25 [2] c9 2b [2] e2 07 [2] cc 25 [2] d8 3e [2] d7 24 [2] c9 39 [2] cb 38 [2] d0 3e [2] cc 39 [2] d0 16 }

  condition:
    any of them
}