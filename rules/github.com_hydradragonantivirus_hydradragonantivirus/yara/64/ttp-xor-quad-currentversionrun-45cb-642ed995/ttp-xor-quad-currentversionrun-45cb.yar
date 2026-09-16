rule TTP_XOR_QUAD_CurrentVersionRun_45cb {
  strings:
    $key_45cb = { 16 a4 [2] 32 aa [2] 19 86 [2] 37 a4 [2] 23 bf [2] 2c a5 [2] 32 b8 [2] 30 b9 [2] 2b bf [2] 37 b8 [2] 2b 97 }

  condition:
    any of them
}