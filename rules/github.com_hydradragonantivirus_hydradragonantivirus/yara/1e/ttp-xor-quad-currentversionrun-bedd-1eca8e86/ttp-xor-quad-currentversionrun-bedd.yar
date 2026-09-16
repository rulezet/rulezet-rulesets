rule TTP_XOR_QUAD_CurrentVersionRun_bedd {
  strings:
    $key_bedd = { ed b2 [2] c9 bc [2] e2 90 [2] cc b2 [2] d8 a9 [2] d7 b3 [2] c9 ae [2] cb af [2] d0 a9 [2] cc ae [2] d0 81 }

  condition:
    any of them
}