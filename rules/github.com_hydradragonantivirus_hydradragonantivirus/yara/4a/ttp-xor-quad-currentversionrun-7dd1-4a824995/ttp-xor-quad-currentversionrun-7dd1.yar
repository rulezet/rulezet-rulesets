rule TTP_XOR_QUAD_CurrentVersionRun_7dd1 {
  strings:
    $key_7dd1 = { 2e be [2] 0a b0 [2] 21 9c [2] 0f be [2] 1b a5 [2] 14 bf [2] 0a a2 [2] 08 a3 [2] 13 a5 [2] 0f a2 [2] 13 8d }

  condition:
    any of them
}