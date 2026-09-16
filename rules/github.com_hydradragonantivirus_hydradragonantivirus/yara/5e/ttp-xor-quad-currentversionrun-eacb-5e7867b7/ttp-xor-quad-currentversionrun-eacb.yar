rule TTP_XOR_QUAD_CurrentVersionRun_eacb {
  strings:
    $key_eacb = { b9 a4 [2] 9d aa [2] b6 86 [2] 98 a4 [2] 8c bf [2] 83 a5 [2] 9d b8 [2] 9f b9 [2] 84 bf [2] 98 b8 [2] 84 97 }

  condition:
    any of them
}