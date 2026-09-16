rule TTP_XOR_QUAD_CurrentVersionRun_e1cd {
  strings:
    $key_e1cd = { b2 a2 [2] 96 ac [2] bd 80 [2] 93 a2 [2] 87 b9 [2] 88 a3 [2] 96 be [2] 94 bf [2] 8f b9 [2] 93 be [2] 8f 91 }

  condition:
    any of them
}