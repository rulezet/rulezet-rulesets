rule TTP_XOR_QUAD_CurrentVersionRun_f7be {
  strings:
    $key_f7be = { a4 d1 [2] 80 df [2] ab f3 [2] 85 d1 [2] 91 ca [2] 9e d0 [2] 80 cd [2] 82 cc [2] 99 ca [2] 85 cd [2] 99 e2 }

  condition:
    any of them
}