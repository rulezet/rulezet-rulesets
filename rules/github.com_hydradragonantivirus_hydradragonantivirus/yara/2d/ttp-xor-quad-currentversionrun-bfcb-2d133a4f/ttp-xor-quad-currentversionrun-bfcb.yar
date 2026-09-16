rule TTP_XOR_QUAD_CurrentVersionRun_bfcb {
  strings:
    $key_bfcb = { ec a4 [2] c8 aa [2] e3 86 [2] cd a4 [2] d9 bf [2] d6 a5 [2] c8 b8 [2] ca b9 [2] d1 bf [2] cd b8 [2] d1 97 }

  condition:
    any of them
}