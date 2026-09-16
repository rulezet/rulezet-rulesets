rule TTP_XOR_QUAD_CurrentVersionRun_75cb {
  strings:
    $key_75cb = { 26 a4 [2] 02 aa [2] 29 86 [2] 07 a4 [2] 13 bf [2] 1c a5 [2] 02 b8 [2] 00 b9 [2] 1b bf [2] 07 b8 [2] 1b 97 }

  condition:
    any of them
}