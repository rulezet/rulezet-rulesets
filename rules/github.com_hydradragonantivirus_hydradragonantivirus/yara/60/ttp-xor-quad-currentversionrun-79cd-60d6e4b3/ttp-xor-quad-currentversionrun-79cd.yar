rule TTP_XOR_QUAD_CurrentVersionRun_79cd {
  strings:
    $key_79cd = { 2a a2 [2] 0e ac [2] 25 80 [2] 0b a2 [2] 1f b9 [2] 10 a3 [2] 0e be [2] 0c bf [2] 17 b9 [2] 0b be [2] 17 91 }

  condition:
    any of them
}