rule TTP_XOR_QUAD_CurrentVersionRun_5ccb {
  strings:
    $key_5ccb = { 0f a4 [2] 2b aa [2] 00 86 [2] 2e a4 [2] 3a bf [2] 35 a5 [2] 2b b8 [2] 29 b9 [2] 32 bf [2] 2e b8 [2] 32 97 }

  condition:
    any of them
}