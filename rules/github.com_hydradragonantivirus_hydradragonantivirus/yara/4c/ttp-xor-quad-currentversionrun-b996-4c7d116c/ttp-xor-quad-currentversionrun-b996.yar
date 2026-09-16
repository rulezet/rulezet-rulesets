rule TTP_XOR_QUAD_CurrentVersionRun_b996 {
  strings:
    $key_b996 = { ea f9 [2] ce f7 [2] e5 db [2] cb f9 [2] df e2 [2] d0 f8 [2] ce e5 [2] cc e4 [2] d7 e2 [2] cb e5 [2] d7 ca }

  condition:
    any of them
}