rule TTP_XOR_QUAD_CurrentVersionRun_fecb {
  strings:
    $key_fecb = { ad a4 [2] 89 aa [2] a2 86 [2] 8c a4 [2] 98 bf [2] 97 a5 [2] 89 b8 [2] 8b b9 [2] 90 bf [2] 8c b8 [2] 90 97 }

  condition:
    any of them
}