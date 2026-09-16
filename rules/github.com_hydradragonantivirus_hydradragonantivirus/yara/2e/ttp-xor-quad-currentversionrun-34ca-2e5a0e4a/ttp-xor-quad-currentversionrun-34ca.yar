rule TTP_XOR_QUAD_CurrentVersionRun_34ca {
  strings:
    $key_34ca = { 67 a5 [2] 43 ab [2] 68 87 [2] 46 a5 [2] 52 be [2] 5d a4 [2] 43 b9 [2] 41 b8 [2] 5a be [2] 46 b9 [2] 5a 96 }

  condition:
    any of them
}