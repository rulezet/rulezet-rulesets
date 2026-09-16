rule TTP_XOR_QUAD_CurrentVersionRun_dad0 {
  strings:
    $key_dad0 = { 89 bf [2] ad b1 [2] 86 9d [2] a8 bf [2] bc a4 [2] b3 be [2] ad a3 [2] af a2 [2] b4 a4 [2] a8 a3 [2] b4 8c }

  condition:
    any of them
}