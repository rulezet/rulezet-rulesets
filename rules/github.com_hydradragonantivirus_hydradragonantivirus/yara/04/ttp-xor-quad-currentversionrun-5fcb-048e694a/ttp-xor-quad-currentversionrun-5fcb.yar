rule TTP_XOR_QUAD_CurrentVersionRun_5fcb {
  strings:
    $key_5fcb = { 0c a4 [2] 28 aa [2] 03 86 [2] 2d a4 [2] 39 bf [2] 36 a5 [2] 28 b8 [2] 2a b9 [2] 31 bf [2] 2d b8 [2] 31 97 }

  condition:
    any of them
}