rule TTP_XOR_QUAD_CurrentVersionRun_00cb {
  strings:
    $key_00cb = { 53 a4 [2] 77 aa [2] 5c 86 [2] 72 a4 [2] 66 bf [2] 69 a5 [2] 77 b8 [2] 75 b9 [2] 6e bf [2] 72 b8 [2] 6e 97 }

  condition:
    any of them
}