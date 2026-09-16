rule TTP_XOR_QUAD_CurrentVersionRun_2fcd {
  strings:
    $key_2fcd = { 7c a2 [2] 58 ac [2] 73 80 [2] 5d a2 [2] 49 b9 [2] 46 a3 [2] 58 be [2] 5a bf [2] 41 b9 [2] 5d be [2] 41 91 }

  condition:
    any of them
}