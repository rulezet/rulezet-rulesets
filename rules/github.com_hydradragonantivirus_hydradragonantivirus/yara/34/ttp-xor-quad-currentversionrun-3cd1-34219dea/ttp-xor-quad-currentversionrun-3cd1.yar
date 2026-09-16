rule TTP_XOR_QUAD_CurrentVersionRun_3cd1 {
  strings:
    $key_3cd1 = { 6f be [2] 4b b0 [2] 60 9c [2] 4e be [2] 5a a5 [2] 55 bf [2] 4b a2 [2] 49 a3 [2] 52 a5 [2] 4e a2 [2] 52 8d }

  condition:
    any of them
}