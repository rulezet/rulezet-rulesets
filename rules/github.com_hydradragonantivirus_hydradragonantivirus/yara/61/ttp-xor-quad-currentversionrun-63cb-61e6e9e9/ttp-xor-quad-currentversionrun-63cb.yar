rule TTP_XOR_QUAD_CurrentVersionRun_63cb {
  strings:
    $key_63cb = { 30 a4 [2] 14 aa [2] 3f 86 [2] 11 a4 [2] 05 bf [2] 0a a5 [2] 14 b8 [2] 16 b9 [2] 0d bf [2] 11 b8 [2] 0d 97 }

  condition:
    any of them
}