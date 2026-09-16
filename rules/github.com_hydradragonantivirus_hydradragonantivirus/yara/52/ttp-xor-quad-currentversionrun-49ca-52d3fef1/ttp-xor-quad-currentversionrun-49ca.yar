rule TTP_XOR_QUAD_CurrentVersionRun_49ca {
  strings:
    $key_49ca = { 1a a5 [2] 3e ab [2] 15 87 [2] 3b a5 [2] 2f be [2] 20 a4 [2] 3e b9 [2] 3c b8 [2] 27 be [2] 3b b9 [2] 27 96 }

  condition:
    any of them
}