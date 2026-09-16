rule TTP_XOR_QUAD_CurrentVersionRun_11cb {
  strings:
    $key_11cb = { 42 a4 [2] 66 aa [2] 4d 86 [2] 63 a4 [2] 77 bf [2] 78 a5 [2] 66 b8 [2] 64 b9 [2] 7f bf [2] 63 b8 [2] 7f 97 }

  condition:
    any of them
}