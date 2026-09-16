rule TTP_XOR_QUAD_CurrentVersionRun_d3cd {
  strings:
    $key_d3cd = { 80 a2 [2] a4 ac [2] 8f 80 [2] a1 a2 [2] b5 b9 [2] ba a3 [2] a4 be [2] a6 bf [2] bd b9 [2] a1 be [2] bd 91 }

  condition:
    any of them
}