rule TTP_XOR_QUAD_CurrentVersionRun_0dcb {
  strings:
    $key_0dcb = { 5e a4 [2] 7a aa [2] 51 86 [2] 7f a4 [2] 6b bf [2] 64 a5 [2] 7a b8 [2] 78 b9 [2] 63 bf [2] 7f b8 [2] 63 97 }

  condition:
    any of them
}