rule TTP_XOR_QUAD_CurrentVersionRun_15d0 {
  strings:
    $key_15d0 = { 46 bf [2] 62 b1 [2] 49 9d [2] 67 bf [2] 73 a4 [2] 7c be [2] 62 a3 [2] 60 a2 [2] 7b a4 [2] 67 a3 [2] 7b 8c }

  condition:
    any of them
}