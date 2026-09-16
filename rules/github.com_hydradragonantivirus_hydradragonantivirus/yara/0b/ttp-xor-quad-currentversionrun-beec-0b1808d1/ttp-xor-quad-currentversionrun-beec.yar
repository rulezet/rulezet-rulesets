rule TTP_XOR_QUAD_CurrentVersionRun_beec {
  strings:
    $key_beec = { ed 83 [2] c9 8d [2] e2 a1 [2] cc 83 [2] d8 98 [2] d7 82 [2] c9 9f [2] cb 9e [2] d0 98 [2] cc 9f [2] d0 b0 }

  condition:
    any of them
}