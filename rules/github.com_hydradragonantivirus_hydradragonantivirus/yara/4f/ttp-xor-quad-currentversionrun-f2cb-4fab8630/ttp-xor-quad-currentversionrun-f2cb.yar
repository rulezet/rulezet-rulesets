rule TTP_XOR_QUAD_CurrentVersionRun_f2cb {
  strings:
    $key_f2cb = { a1 a4 [2] 85 aa [2] ae 86 [2] 80 a4 [2] 94 bf [2] 9b a5 [2] 85 b8 [2] 87 b9 [2] 9c bf [2] 80 b8 [2] 9c 97 }

  condition:
    any of them
}