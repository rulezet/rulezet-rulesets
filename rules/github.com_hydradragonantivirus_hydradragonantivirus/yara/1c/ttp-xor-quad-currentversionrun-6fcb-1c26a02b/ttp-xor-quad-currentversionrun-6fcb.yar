rule TTP_XOR_QUAD_CurrentVersionRun_6fcb {
  strings:
    $key_6fcb = { 3c a4 [2] 18 aa [2] 33 86 [2] 1d a4 [2] 09 bf [2] 06 a5 [2] 18 b8 [2] 1a b9 [2] 01 bf [2] 1d b8 [2] 01 97 }

  condition:
    any of them
}