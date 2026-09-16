rule TTP_XOR_QUAD_CurrentVersionRun_bece {
  strings:
    $key_bece = { ed a1 [2] c9 af [2] e2 83 [2] cc a1 [2] d8 ba [2] d7 a0 [2] c9 bd [2] cb bc [2] d0 ba [2] cc bd [2] d0 92 }

  condition:
    any of them
}