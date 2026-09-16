rule TTP_XOR_QUAD_CurrentVersionRun_09ca {
  strings:
    $key_09ca = { 5a a5 [2] 7e ab [2] 55 87 [2] 7b a5 [2] 6f be [2] 60 a4 [2] 7e b9 [2] 7c b8 [2] 67 be [2] 7b b9 [2] 67 96 }

  condition:
    any of them
}