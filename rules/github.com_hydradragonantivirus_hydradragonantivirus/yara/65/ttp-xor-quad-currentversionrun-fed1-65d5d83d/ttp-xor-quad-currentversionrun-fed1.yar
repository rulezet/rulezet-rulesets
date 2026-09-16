rule TTP_XOR_QUAD_CurrentVersionRun_fed1 {
  strings:
    $key_fed1 = { ad be [2] 89 b0 [2] a2 9c [2] 8c be [2] 98 a5 [2] 97 bf [2] 89 a2 [2] 8b a3 [2] 90 a5 [2] 8c a2 [2] 90 8d }

  condition:
    any of them
}