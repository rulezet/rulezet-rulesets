rule TTP_XOR_QUAD_CurrentVersionRun_0acb {
  strings:
    $key_0acb = { 59 a4 [2] 7d aa [2] 56 86 [2] 78 a4 [2] 6c bf [2] 63 a5 [2] 7d b8 [2] 7f b9 [2] 64 bf [2] 78 b8 [2] 64 97 }

  condition:
    any of them
}