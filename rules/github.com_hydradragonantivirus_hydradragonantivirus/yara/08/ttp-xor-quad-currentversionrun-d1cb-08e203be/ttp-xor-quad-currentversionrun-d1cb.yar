rule TTP_XOR_QUAD_CurrentVersionRun_d1cb {
  strings:
    $key_d1cb = { 82 a4 [2] a6 aa [2] 8d 86 [2] a3 a4 [2] b7 bf [2] b8 a5 [2] a6 b8 [2] a4 b9 [2] bf bf [2] a3 b8 [2] bf 97 }

  condition:
    any of them
}