rule TTP_XOR_QUAD_CurrentVersionRun_00cd {
  strings:
    $key_00cd = { 53 a2 [2] 77 ac [2] 5c 80 [2] 72 a2 [2] 66 b9 [2] 69 a3 [2] 77 be [2] 75 bf [2] 6e b9 [2] 72 be [2] 6e 91 }

  condition:
    any of them
}