rule TTP_XOR_QUAD_CurrentVersionRun_66cb {
  strings:
    $key_66cb = { 35 a4 [2] 11 aa [2] 3a 86 [2] 14 a4 [2] 00 bf [2] 0f a5 [2] 11 b8 [2] 13 b9 [2] 08 bf [2] 14 b8 [2] 08 97 }

  condition:
    any of them
}