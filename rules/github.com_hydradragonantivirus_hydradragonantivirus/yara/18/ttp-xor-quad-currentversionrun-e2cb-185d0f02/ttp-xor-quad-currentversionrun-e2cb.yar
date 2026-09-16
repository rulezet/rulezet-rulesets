rule TTP_XOR_QUAD_CurrentVersionRun_e2cb {
  strings:
    $key_e2cb = { b1 a4 [2] 95 aa [2] be 86 [2] 90 a4 [2] 84 bf [2] 8b a5 [2] 95 b8 [2] 97 b9 [2] 8c bf [2] 90 b8 [2] 8c 97 }

  condition:
    any of them
}