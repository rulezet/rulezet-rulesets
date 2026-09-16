rule TTP_XOR_QUAD_CurrentVersionRun_b9ce {
  strings:
    $key_b9ce = { ea a1 [2] ce af [2] e5 83 [2] cb a1 [2] df ba [2] d0 a0 [2] ce bd [2] cc bc [2] d7 ba [2] cb bd [2] d7 92 }

  condition:
    any of them
}