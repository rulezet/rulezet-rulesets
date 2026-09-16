rule TTP_XOR_QUAD_CurrentVersionRun_918a {
  strings:
    $key_918a = { c2 e5 [2] e6 eb [2] cd c7 [2] e3 e5 [2] f7 fe [2] f8 e4 [2] e6 f9 [2] e4 f8 [2] ff fe [2] e3 f9 [2] ff d6 }

  condition:
    any of them
}