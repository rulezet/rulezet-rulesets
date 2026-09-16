rule TTP_XOR_QUAD_CurrentVersionRun_15cb {
  strings:
    $key_15cb = { 46 a4 [2] 62 aa [2] 49 86 [2] 67 a4 [2] 73 bf [2] 7c a5 [2] 62 b8 [2] 60 b9 [2] 7b bf [2] 67 b8 [2] 7b 97 }

  condition:
    any of them
}