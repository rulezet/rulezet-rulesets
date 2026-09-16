rule TTP_XOR_QUAD_CurrentVersionRun_38cd {
  strings:
    $key_38cd = { 6b a2 [2] 4f ac [2] 64 80 [2] 4a a2 [2] 5e b9 [2] 51 a3 [2] 4f be [2] 4d bf [2] 56 b9 [2] 4a be [2] 56 91 }

  condition:
    any of them
}