rule TTP_XOR_QUAD_CurrentVersionRun_c4cb {
  strings:
    $key_c4cb = { 97 a4 [2] b3 aa [2] 98 86 [2] b6 a4 [2] a2 bf [2] ad a5 [2] b3 b8 [2] b1 b9 [2] aa bf [2] b6 b8 [2] aa 97 }

  condition:
    any of them
}