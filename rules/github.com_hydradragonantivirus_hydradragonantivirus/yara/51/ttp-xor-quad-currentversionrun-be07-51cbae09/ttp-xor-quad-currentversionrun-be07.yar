rule TTP_XOR_QUAD_CurrentVersionRun_be07 {
  strings:
    $key_be07 = { ed 68 [2] c9 66 [2] e2 4a [2] cc 68 [2] d8 73 [2] d7 69 [2] c9 74 [2] cb 75 [2] d0 73 [2] cc 74 [2] d0 5b }

  condition:
    any of them
}