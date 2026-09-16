rule TTP_XOR_QUAD_CurrentVersionRun_be11 {
  strings:
    $key_be11 = { ed 7e [2] c9 70 [2] e2 5c [2] cc 7e [2] d8 65 [2] d7 7f [2] c9 62 [2] cb 63 [2] d0 65 [2] cc 62 [2] d0 4d }

  condition:
    any of them
}