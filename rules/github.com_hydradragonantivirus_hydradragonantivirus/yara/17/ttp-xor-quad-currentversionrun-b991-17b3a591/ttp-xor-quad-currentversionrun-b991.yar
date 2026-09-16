rule TTP_XOR_QUAD_CurrentVersionRun_b991 {
  strings:
    $key_b991 = { ea fe [2] ce f0 [2] e5 dc [2] cb fe [2] df e5 [2] d0 ff [2] ce e2 [2] cc e3 [2] d7 e5 [2] cb e2 [2] d7 cd }

  condition:
    any of them
}