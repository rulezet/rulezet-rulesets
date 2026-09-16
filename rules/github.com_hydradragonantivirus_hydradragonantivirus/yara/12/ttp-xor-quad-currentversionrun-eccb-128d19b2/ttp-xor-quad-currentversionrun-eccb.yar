rule TTP_XOR_QUAD_CurrentVersionRun_eccb {
  strings:
    $key_eccb = { bf a4 [2] 9b aa [2] b0 86 [2] 9e a4 [2] 8a bf [2] 85 a5 [2] 9b b8 [2] 99 b9 [2] 82 bf [2] 9e b8 [2] 82 97 }

  condition:
    any of them
}