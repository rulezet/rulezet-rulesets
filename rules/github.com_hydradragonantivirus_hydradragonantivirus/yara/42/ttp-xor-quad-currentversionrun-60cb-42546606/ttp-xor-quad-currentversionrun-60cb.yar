rule TTP_XOR_QUAD_CurrentVersionRun_60cb {
  strings:
    $key_60cb = { 33 a4 [2] 17 aa [2] 3c 86 [2] 12 a4 [2] 06 bf [2] 09 a5 [2] 17 b8 [2] 15 b9 [2] 0e bf [2] 12 b8 [2] 0e 97 }

  condition:
    any of them
}