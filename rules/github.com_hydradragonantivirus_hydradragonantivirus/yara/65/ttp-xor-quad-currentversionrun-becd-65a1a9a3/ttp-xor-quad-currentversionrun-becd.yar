rule TTP_XOR_QUAD_CurrentVersionRun_becd {
  strings:
    $key_becd = { ed a2 [2] c9 ac [2] e2 80 [2] cc a2 [2] d8 b9 [2] d7 a3 [2] c9 be [2] cb bf [2] d0 b9 [2] cc be [2] d0 91 }

  condition:
    any of them
}