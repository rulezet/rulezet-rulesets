rule TTP_XOR_QUAD_CurrentVersionRun_6ecb {
  strings:
    $key_6ecb = { 3d a4 [2] 19 aa [2] 32 86 [2] 1c a4 [2] 08 bf [2] 07 a5 [2] 19 b8 [2] 1b b9 [2] 00 bf [2] 1c b8 [2] 00 97 }

  condition:
    any of them
}