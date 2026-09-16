rule TTP_XOR_QUAD_CurrentVersionRun_17cd {
  strings:
    $key_17cd = { 44 a2 [2] 60 ac [2] 4b 80 [2] 65 a2 [2] 71 b9 [2] 7e a3 [2] 60 be [2] 62 bf [2] 79 b9 [2] 65 be [2] 79 91 }

  condition:
    any of them
}