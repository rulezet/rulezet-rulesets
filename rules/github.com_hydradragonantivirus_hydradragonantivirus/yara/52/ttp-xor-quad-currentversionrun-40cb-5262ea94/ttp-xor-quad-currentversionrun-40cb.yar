rule TTP_XOR_QUAD_CurrentVersionRun_40cb {
  strings:
    $key_40cb = { 13 a4 [2] 37 aa [2] 1c 86 [2] 32 a4 [2] 26 bf [2] 29 a5 [2] 37 b8 [2] 35 b9 [2] 2e bf [2] 32 b8 [2] 2e 97 }

  condition:
    any of them
}