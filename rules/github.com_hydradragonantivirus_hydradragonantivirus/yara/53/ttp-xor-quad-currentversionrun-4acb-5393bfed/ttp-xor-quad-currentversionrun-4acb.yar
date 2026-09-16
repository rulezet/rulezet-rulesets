rule TTP_XOR_QUAD_CurrentVersionRun_4acb {
  strings:
    $key_4acb = { 19 a4 [2] 3d aa [2] 16 86 [2] 38 a4 [2] 2c bf [2] 23 a5 [2] 3d b8 [2] 3f b9 [2] 24 bf [2] 38 b8 [2] 24 97 }

  condition:
    any of them
}