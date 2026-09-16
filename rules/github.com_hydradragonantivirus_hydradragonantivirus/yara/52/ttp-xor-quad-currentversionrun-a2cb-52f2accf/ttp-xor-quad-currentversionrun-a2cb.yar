rule TTP_XOR_QUAD_CurrentVersionRun_a2cb {
  strings:
    $key_a2cb = { f1 a4 [2] d5 aa [2] fe 86 [2] d0 a4 [2] c4 bf [2] cb a5 [2] d5 b8 [2] d7 b9 [2] cc bf [2] d0 b8 [2] cc 97 }

  condition:
    any of them
}