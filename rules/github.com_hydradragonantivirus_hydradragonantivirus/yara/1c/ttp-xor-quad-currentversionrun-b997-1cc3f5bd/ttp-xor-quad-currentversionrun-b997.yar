rule TTP_XOR_QUAD_CurrentVersionRun_b997 {
  strings:
    $key_b997 = { ea f8 [2] ce f6 [2] e5 da [2] cb f8 [2] df e3 [2] d0 f9 [2] ce e4 [2] cc e5 [2] d7 e3 [2] cb e4 [2] d7 cb }

  condition:
    any of them
}