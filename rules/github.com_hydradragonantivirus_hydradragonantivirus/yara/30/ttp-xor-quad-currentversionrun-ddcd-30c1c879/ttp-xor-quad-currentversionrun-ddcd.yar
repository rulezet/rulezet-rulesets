rule TTP_XOR_QUAD_CurrentVersionRun_ddcd {
  strings:
    $key_ddcd = { 8e a2 [2] aa ac [2] 81 80 [2] af a2 [2] bb b9 [2] b4 a3 [2] aa be [2] a8 bf [2] b3 b9 [2] af be [2] b3 91 }

  condition:
    any of them
}