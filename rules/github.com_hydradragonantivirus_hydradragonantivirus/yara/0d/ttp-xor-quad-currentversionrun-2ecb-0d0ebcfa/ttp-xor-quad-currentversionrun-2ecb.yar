rule TTP_XOR_QUAD_CurrentVersionRun_2ecb {
  strings:
    $key_2ecb = { 7d a4 [2] 59 aa [2] 72 86 [2] 5c a4 [2] 48 bf [2] 47 a5 [2] 59 b8 [2] 5b b9 [2] 40 bf [2] 5c b8 [2] 40 97 }

  condition:
    any of them
}