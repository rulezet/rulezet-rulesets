rule TTP_XOR_QUAD_CurrentVersionRun_29cb {
  strings:
    $key_29cb = { 7a a4 [2] 5e aa [2] 75 86 [2] 5b a4 [2] 4f bf [2] 40 a5 [2] 5e b8 [2] 5c b9 [2] 47 bf [2] 5b b8 [2] 47 97 }

  condition:
    any of them
}