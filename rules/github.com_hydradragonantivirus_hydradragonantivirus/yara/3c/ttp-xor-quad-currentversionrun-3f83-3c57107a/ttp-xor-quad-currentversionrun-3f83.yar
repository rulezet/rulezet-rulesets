rule TTP_XOR_QUAD_CurrentVersionRun_3f83 {
  strings:
    $key_3f83 = { 6c ec [2] 48 e2 [2] 63 ce [2] 4d ec [2] 59 f7 [2] 56 ed [2] 48 f0 [2] 4a f1 [2] 51 f7 [2] 4d f0 [2] 51 df }

  condition:
    any of them
}