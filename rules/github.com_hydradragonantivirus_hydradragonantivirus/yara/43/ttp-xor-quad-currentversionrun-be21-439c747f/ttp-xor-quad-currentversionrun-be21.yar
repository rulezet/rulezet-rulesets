rule TTP_XOR_QUAD_CurrentVersionRun_be21 {
  strings:
    $key_be21 = { ed 4e [2] c9 40 [2] e2 6c [2] cc 4e [2] d8 55 [2] d7 4f [2] c9 52 [2] cb 53 [2] d0 55 [2] cc 52 [2] d0 7d }

  condition:
    any of them
}