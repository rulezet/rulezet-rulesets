rule TTP_XOR_QUAD_CurrentVersionRun_a5dc {
  strings:
    $key_a5dc = { f6 b3 [2] d2 bd [2] f9 91 [2] d7 b3 [2] c3 a8 [2] cc b2 [2] d2 af [2] d0 ae [2] cb a8 [2] d7 af [2] cb 80 }

  condition:
    any of them
}