rule TTP_XOR_QUAD_CurrentVersionRun_2ccb {
  strings:
    $key_2ccb = { 7f a4 [2] 5b aa [2] 70 86 [2] 5e a4 [2] 4a bf [2] 45 a5 [2] 5b b8 [2] 59 b9 [2] 42 bf [2] 5e b8 [2] 42 97 }

  condition:
    any of them
}