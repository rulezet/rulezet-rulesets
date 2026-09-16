rule TTP_XOR_QUAD_CurrentVersionRun_5fcd {
  strings:
    $key_5fcd = { 0c a2 [2] 28 ac [2] 03 80 [2] 2d a2 [2] 39 b9 [2] 36 a3 [2] 28 be [2] 2a bf [2] 31 b9 [2] 2d be [2] 31 91 }

  condition:
    any of them
}