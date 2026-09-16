rule TTP_XOR_QUAD_CurrentVersionRun_16cb {
  strings:
    $key_16cb = { 45 a4 [2] 61 aa [2] 4a 86 [2] 64 a4 [2] 70 bf [2] 7f a5 [2] 61 b8 [2] 63 b9 [2] 78 bf [2] 64 b8 [2] 78 97 }

  condition:
    any of them
}