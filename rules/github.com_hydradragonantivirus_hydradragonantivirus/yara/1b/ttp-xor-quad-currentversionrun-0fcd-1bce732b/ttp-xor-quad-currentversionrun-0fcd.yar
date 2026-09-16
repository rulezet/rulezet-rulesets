rule TTP_XOR_QUAD_CurrentVersionRun_0fcd {
  strings:
    $key_0fcd = { 5c a2 [2] 78 ac [2] 53 80 [2] 7d a2 [2] 69 b9 [2] 66 a3 [2] 78 be [2] 7a bf [2] 61 b9 [2] 7d be [2] 61 91 }

  condition:
    any of them
}