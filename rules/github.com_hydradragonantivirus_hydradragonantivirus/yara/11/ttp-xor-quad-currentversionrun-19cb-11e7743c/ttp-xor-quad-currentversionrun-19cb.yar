rule TTP_XOR_QUAD_CurrentVersionRun_19cb {
  strings:
    $key_19cb = { 4a a4 [2] 6e aa [2] 45 86 [2] 6b a4 [2] 7f bf [2] 70 a5 [2] 6e b8 [2] 6c b9 [2] 77 bf [2] 6b b8 [2] 77 97 }

  condition:
    any of them
}