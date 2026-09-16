rule TTP_XOR_QUAD_CurrentVersionRun_e4cb {
  strings:
    $key_e4cb = { b7 a4 [2] 93 aa [2] b8 86 [2] 96 a4 [2] 82 bf [2] 8d a5 [2] 93 b8 [2] 91 b9 [2] 8a bf [2] 96 b8 [2] 8a 97 }

  condition:
    any of them
}