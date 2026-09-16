rule TTP_XOR_QUAD_CurrentVersionRun_f181 {
  strings:
    $key_f181 = { a2 ee [2] 86 e0 [2] ad cc [2] 83 ee [2] 97 f5 [2] 98 ef [2] 86 f2 [2] 84 f3 [2] 9f f5 [2] 83 f2 [2] 9f dd }

  condition:
    any of them
}