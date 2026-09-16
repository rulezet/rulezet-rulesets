rule TTP_XOR_QUAD_CurrentVersionRun_6ccb {
  strings:
    $key_6ccb = { 3f a4 [2] 1b aa [2] 30 86 [2] 1e a4 [2] 0a bf [2] 05 a5 [2] 1b b8 [2] 19 b9 [2] 02 bf [2] 1e b8 [2] 02 97 }

  condition:
    any of them
}