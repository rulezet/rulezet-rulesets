rule TTP_XOR_QUAD_CurrentVersionRun_2fcb {
  strings:
    $key_2fcb = { 7c a4 [2] 58 aa [2] 73 86 [2] 5d a4 [2] 49 bf [2] 46 a5 [2] 58 b8 [2] 5a b9 [2] 41 bf [2] 5d b8 [2] 41 97 }

  condition:
    any of them
}