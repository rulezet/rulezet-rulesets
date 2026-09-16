rule TTP_XOR_QUAD_CurrentVersionRun_a5cb {
  strings:
    $key_a5cb = { f6 a4 [2] d2 aa [2] f9 86 [2] d7 a4 [2] c3 bf [2] cc a5 [2] d2 b8 [2] d0 b9 [2] cb bf [2] d7 b8 [2] cb 97 }

  condition:
    any of them
}