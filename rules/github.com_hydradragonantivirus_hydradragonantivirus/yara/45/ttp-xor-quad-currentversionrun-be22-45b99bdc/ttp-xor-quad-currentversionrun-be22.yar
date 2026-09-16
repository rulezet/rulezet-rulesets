rule TTP_XOR_QUAD_CurrentVersionRun_be22 {
  strings:
    $key_be22 = { ed 4d [2] c9 43 [2] e2 6f [2] cc 4d [2] d8 56 [2] d7 4c [2] c9 51 [2] cb 50 [2] d0 56 [2] cc 51 [2] d0 7e }

  condition:
    any of them
}