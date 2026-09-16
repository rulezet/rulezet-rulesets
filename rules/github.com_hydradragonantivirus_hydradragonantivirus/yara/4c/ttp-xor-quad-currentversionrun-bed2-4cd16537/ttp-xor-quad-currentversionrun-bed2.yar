rule TTP_XOR_QUAD_CurrentVersionRun_bed2 {
  strings:
    $key_bed2 = { ed bd [2] c9 b3 [2] e2 9f [2] cc bd [2] d8 a6 [2] d7 bc [2] c9 a1 [2] cb a0 [2] d0 a6 [2] cc a1 [2] d0 8e }

  condition:
    any of them
}