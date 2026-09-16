rule TTP_XOR_QUAD_CurrentVersionRun_08cd {
  strings:
    $key_08cd = { 5b a2 [2] 7f ac [2] 54 80 [2] 7a a2 [2] 6e b9 [2] 61 a3 [2] 7f be [2] 7d bf [2] 66 b9 [2] 7a be [2] 66 91 }

  condition:
    any of them
}