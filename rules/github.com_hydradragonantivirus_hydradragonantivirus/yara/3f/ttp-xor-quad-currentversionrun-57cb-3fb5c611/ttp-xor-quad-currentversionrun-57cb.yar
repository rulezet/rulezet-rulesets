rule TTP_XOR_QUAD_CurrentVersionRun_57cb {
  strings:
    $key_57cb = { 04 a4 [2] 20 aa [2] 0b 86 [2] 25 a4 [2] 31 bf [2] 3e a5 [2] 20 b8 [2] 22 b9 [2] 39 bf [2] 25 b8 [2] 39 97 }

  condition:
    any of them
}