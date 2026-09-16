rule TTP_XOR_QUAD_CurrentVersionRun_25cb {
  strings:
    $key_25cb = { 76 a4 [2] 52 aa [2] 79 86 [2] 57 a4 [2] 43 bf [2] 4c a5 [2] 52 b8 [2] 50 b9 [2] 4b bf [2] 57 b8 [2] 4b 97 }

  condition:
    any of them
}