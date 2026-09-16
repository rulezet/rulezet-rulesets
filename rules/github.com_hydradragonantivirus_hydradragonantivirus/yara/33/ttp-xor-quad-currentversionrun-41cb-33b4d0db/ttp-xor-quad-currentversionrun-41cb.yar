rule TTP_XOR_QUAD_CurrentVersionRun_41cb {
  strings:
    $key_41cb = { 12 a4 [2] 36 aa [2] 1d 86 [2] 33 a4 [2] 27 bf [2] 28 a5 [2] 36 b8 [2] 34 b9 [2] 2f bf [2] 33 b8 [2] 2f 97 }

  condition:
    any of them
}