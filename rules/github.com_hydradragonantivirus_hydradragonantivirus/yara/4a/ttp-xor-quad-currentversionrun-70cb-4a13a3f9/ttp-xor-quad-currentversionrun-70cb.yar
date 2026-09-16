rule TTP_XOR_QUAD_CurrentVersionRun_70cb {
  strings:
    $key_70cb = { 23 a4 [2] 07 aa [2] 2c 86 [2] 02 a4 [2] 16 bf [2] 19 a5 [2] 07 b8 [2] 05 b9 [2] 1e bf [2] 02 b8 [2] 1e 97 }

  condition:
    any of them
}