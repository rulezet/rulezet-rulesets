rule TTP_XOR_QUAD_CurrentVersionRun_d0cb {
  strings:
    $key_d0cb = { 83 a4 [2] a7 aa [2] 8c 86 [2] a2 a4 [2] b6 bf [2] b9 a5 [2] a7 b8 [2] a5 b9 [2] be bf [2] a2 b8 [2] be 97 }

  condition:
    any of them
}