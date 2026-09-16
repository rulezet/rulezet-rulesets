rule TTP_XOR_QUAD_CurrentVersionRun_20cb {
  strings:
    $key_20cb = { 73 a4 [2] 57 aa [2] 7c 86 [2] 52 a4 [2] 46 bf [2] 49 a5 [2] 57 b8 [2] 55 b9 [2] 4e bf [2] 52 b8 [2] 4e 97 }

  condition:
    any of them
}