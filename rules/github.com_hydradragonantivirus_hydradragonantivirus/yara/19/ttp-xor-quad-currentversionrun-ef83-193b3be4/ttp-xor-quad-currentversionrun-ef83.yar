rule TTP_XOR_QUAD_CurrentVersionRun_ef83 {
  strings:
    $key_ef83 = { bc ec [2] 98 e2 [2] b3 ce [2] 9d ec [2] 89 f7 [2] 86 ed [2] 98 f0 [2] 9a f1 [2] 81 f7 [2] 9d f0 [2] 81 df }

  condition:
    any of them
}