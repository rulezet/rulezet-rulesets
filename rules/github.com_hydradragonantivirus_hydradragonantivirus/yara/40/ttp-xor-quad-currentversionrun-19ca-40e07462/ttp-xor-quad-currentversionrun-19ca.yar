rule TTP_XOR_QUAD_CurrentVersionRun_19ca {
  strings:
    $key_19ca = { 4a a5 [2] 6e ab [2] 45 87 [2] 6b a5 [2] 7f be [2] 70 a4 [2] 6e b9 [2] 6c b8 [2] 77 be [2] 6b b9 [2] 77 96 }

  condition:
    any of them
}