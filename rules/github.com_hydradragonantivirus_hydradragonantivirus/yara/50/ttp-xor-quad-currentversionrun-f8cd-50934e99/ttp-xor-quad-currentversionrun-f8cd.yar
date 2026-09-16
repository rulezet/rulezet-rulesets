rule TTP_XOR_QUAD_CurrentVersionRun_f8cd {
  strings:
    $key_f8cd = { ab a2 [2] 8f ac [2] a4 80 [2] 8a a2 [2] 9e b9 [2] 91 a3 [2] 8f be [2] 8d bf [2] 96 b9 [2] 8a be [2] 96 91 }

  condition:
    any of them
}