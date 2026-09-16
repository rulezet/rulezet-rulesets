rule TTP_XOR_QUAD_CurrentVersionRun_2acb {
  strings:
    $key_2acb = { 79 a4 [2] 5d aa [2] 76 86 [2] 58 a4 [2] 4c bf [2] 43 a5 [2] 5d b8 [2] 5f b9 [2] 44 bf [2] 58 b8 [2] 44 97 }

  condition:
    any of them
}