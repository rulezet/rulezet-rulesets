rule TTP_XOR_QUAD_CurrentVersionRun_e6cd {
  strings:
    $key_e6cd = { b5 a2 [2] 91 ac [2] ba 80 [2] 94 a2 [2] 80 b9 [2] 8f a3 [2] 91 be [2] 93 bf [2] 88 b9 [2] 94 be [2] 88 91 }

  condition:
    any of them
}