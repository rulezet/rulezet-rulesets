rule TTP_XOR_QUAD_CurrentVersionRun_16aa {
  strings:
    $key_16aa = { 45 c5 [2] 61 cb [2] 4a e7 [2] 64 c5 [2] 70 de [2] 7f c4 [2] 61 d9 [2] 63 d8 [2] 78 de [2] 64 d9 [2] 78 f6 }

  condition:
    any of them
}