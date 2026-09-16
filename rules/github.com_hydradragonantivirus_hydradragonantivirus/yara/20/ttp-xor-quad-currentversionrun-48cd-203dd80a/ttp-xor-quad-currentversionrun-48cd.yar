rule TTP_XOR_QUAD_CurrentVersionRun_48cd {
  strings:
    $key_48cd = { 1b a2 [2] 3f ac [2] 14 80 [2] 3a a2 [2] 2e b9 [2] 21 a3 [2] 3f be [2] 3d bf [2] 26 b9 [2] 3a be [2] 26 91 }

  condition:
    any of them
}