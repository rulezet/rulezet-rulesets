rule TTP_XOR_QUAD_CurrentVersionRun_be28 {
  strings:
    $key_be28 = { ed 47 [2] c9 49 [2] e2 65 [2] cc 47 [2] d8 5c [2] d7 46 [2] c9 5b [2] cb 5a [2] d0 5c [2] cc 5b [2] d0 74 }

  condition:
    any of them
}