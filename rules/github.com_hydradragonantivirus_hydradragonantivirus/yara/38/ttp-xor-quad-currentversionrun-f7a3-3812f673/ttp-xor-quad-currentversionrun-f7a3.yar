rule TTP_XOR_QUAD_CurrentVersionRun_f7a3 {
  strings:
    $key_f7a3 = { a4 cc [2] 80 c2 [2] ab ee [2] 85 cc [2] 91 d7 [2] 9e cd [2] 80 d0 [2] 82 d1 [2] 99 d7 [2] 85 d0 [2] 99 ff }

  condition:
    any of them
}