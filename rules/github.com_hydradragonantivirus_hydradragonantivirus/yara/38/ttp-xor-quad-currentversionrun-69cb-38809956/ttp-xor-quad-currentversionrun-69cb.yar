rule TTP_XOR_QUAD_CurrentVersionRun_69cb {
  strings:
    $key_69cb = { 3a a4 [2] 1e aa [2] 35 86 [2] 1b a4 [2] 0f bf [2] 00 a5 [2] 1e b8 [2] 1c b9 [2] 07 bf [2] 1b b8 [2] 07 97 }

  condition:
    any of them
}