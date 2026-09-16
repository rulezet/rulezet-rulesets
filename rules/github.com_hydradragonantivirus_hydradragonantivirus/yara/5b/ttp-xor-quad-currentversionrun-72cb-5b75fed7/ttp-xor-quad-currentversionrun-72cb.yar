rule TTP_XOR_QUAD_CurrentVersionRun_72cb {
  strings:
    $key_72cb = { 21 a4 [2] 05 aa [2] 2e 86 [2] 00 a4 [2] 14 bf [2] 1b a5 [2] 05 b8 [2] 07 b9 [2] 1c bf [2] 00 b8 [2] 1c 97 }

  condition:
    any of them
}