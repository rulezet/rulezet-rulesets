rule TTP_XOR_QUAD_CurrentVersionRun_d6cb {
  strings:
    $key_d6cb = { 85 a4 [2] a1 aa [2] 8a 86 [2] a4 a4 [2] b0 bf [2] bf a5 [2] a1 b8 [2] a3 b9 [2] b8 bf [2] a4 b8 [2] b8 97 }

  condition:
    any of them
}