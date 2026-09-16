rule TTP_XOR_QUAD_CurrentVersionRun_f1cb {
  strings:
    $key_f1cb = { a2 a4 [2] 86 aa [2] ad 86 [2] 83 a4 [2] 97 bf [2] 98 a5 [2] 86 b8 [2] 84 b9 [2] 9f bf [2] 83 b8 [2] 9f 97 }

  condition:
    any of them
}