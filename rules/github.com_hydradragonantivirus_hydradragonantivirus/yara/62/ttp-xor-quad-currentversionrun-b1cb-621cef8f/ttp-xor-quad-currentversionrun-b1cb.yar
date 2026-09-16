rule TTP_XOR_QUAD_CurrentVersionRun_b1cb {
  strings:
    $key_b1cb = { e2 a4 [2] c6 aa [2] ed 86 [2] c3 a4 [2] d7 bf [2] d8 a5 [2] c6 b8 [2] c4 b9 [2] df bf [2] c3 b8 [2] df 97 }

  condition:
    any of them
}