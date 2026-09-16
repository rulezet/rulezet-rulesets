rule TTP_XOR_QUAD_CurrentVersionRun_55cb {
  strings:
    $key_55cb = { 06 a4 [2] 22 aa [2] 09 86 [2] 27 a4 [2] 33 bf [2] 3c a5 [2] 22 b8 [2] 20 b9 [2] 3b bf [2] 27 b8 [2] 3b 97 }

  condition:
    any of them
}