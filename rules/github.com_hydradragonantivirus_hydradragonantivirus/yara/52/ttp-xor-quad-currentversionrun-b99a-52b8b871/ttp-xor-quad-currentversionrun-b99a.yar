rule TTP_XOR_QUAD_CurrentVersionRun_b99a {
  strings:
    $key_b99a = { ea f5 [2] ce fb [2] e5 d7 [2] cb f5 [2] df ee [2] d0 f4 [2] ce e9 [2] cc e8 [2] d7 ee [2] cb e9 [2] d7 c6 }

  condition:
    any of them
}