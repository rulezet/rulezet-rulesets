rule TTP_XOR_QUAD_CurrentVersionRun_58cb {
  strings:
    $key_58cb = { 0b a4 [2] 2f aa [2] 04 86 [2] 2a a4 [2] 3e bf [2] 31 a5 [2] 2f b8 [2] 2d b9 [2] 36 bf [2] 2a b8 [2] 36 97 }

  condition:
    any of them
}