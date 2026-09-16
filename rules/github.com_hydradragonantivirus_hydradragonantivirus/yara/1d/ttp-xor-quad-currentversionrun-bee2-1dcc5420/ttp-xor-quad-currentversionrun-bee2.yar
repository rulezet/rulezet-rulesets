rule TTP_XOR_QUAD_CurrentVersionRun_bee2 {
  strings:
    $key_bee2 = { ed 8d [2] c9 83 [2] e2 af [2] cc 8d [2] d8 96 [2] d7 8c [2] c9 91 [2] cb 90 [2] d0 96 [2] cc 91 [2] d0 be }

  condition:
    any of them
}