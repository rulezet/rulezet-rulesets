rule TTP_XOR_QUAD_CurrentVersionRun_e3cb {
  strings:
    $key_e3cb = { b0 a4 [2] 94 aa [2] bf 86 [2] 91 a4 [2] 85 bf [2] 8a a5 [2] 94 b8 [2] 96 b9 [2] 8d bf [2] 91 b8 [2] 8d 97 }

  condition:
    any of them
}