rule TTP_XOR_QUAD_CurrentVersionRun_bec8 {
  strings:
    $key_bec8 = { ed a7 [2] c9 a9 [2] e2 85 [2] cc a7 [2] d8 bc [2] d7 a6 [2] c9 bb [2] cb ba [2] d0 bc [2] cc bb [2] d0 94 }

  condition:
    any of them
}