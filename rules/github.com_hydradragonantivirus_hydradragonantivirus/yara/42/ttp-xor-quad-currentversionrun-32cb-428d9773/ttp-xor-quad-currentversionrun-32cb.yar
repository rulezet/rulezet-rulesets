rule TTP_XOR_QUAD_CurrentVersionRun_32cb {
  strings:
    $key_32cb = { 61 a4 [2] 45 aa [2] 6e 86 [2] 40 a4 [2] 54 bf [2] 5b a5 [2] 45 b8 [2] 47 b9 [2] 5c bf [2] 40 b8 [2] 5c 97 }

  condition:
    any of them
}