rule TTP_XOR_QUAD_CurrentVersionRun_68cb {
  strings:
    $key_68cb = { 3b a4 [2] 1f aa [2] 34 86 [2] 1a a4 [2] 0e bf [2] 01 a5 [2] 1f b8 [2] 1d b9 [2] 06 bf [2] 1a b8 [2] 06 97 }

  condition:
    any of them
}