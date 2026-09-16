rule TTP_XOR_QUAD_CurrentVersionRun_f781 {
  strings:
    $key_f781 = { a4 ee [2] 80 e0 [2] ab cc [2] 85 ee [2] 91 f5 [2] 9e ef [2] 80 f2 [2] 82 f3 [2] 99 f5 [2] 85 f2 [2] 99 dd }

  condition:
    any of them
}