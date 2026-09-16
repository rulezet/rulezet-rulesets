rule TTP_XOR_QUAD_CurrentVersionRun_06cd {
  strings:
    $key_06cd = { 55 a2 [2] 71 ac [2] 5a 80 [2] 74 a2 [2] 60 b9 [2] 6f a3 [2] 71 be [2] 73 bf [2] 68 b9 [2] 74 be [2] 68 91 }

  condition:
    any of them
}