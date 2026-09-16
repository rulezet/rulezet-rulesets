rule TTP_XOR_QUAD_CurrentVersionRun_f093 {
  strings:
    $key_f093 = { a3 fc [2] 87 f2 [2] ac de [2] 82 fc [2] 96 e7 [2] 99 fd [2] 87 e0 [2] 85 e1 [2] 9e e7 [2] 82 e0 [2] 9e cf }

  condition:
    any of them
}