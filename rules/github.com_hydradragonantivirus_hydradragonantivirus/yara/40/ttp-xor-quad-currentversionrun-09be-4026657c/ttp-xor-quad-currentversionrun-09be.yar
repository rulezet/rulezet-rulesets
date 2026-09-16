rule TTP_XOR_QUAD_CurrentVersionRun_09be {
  strings:
    $key_09be = { 5a d1 [2] 7e df [2] 55 f3 [2] 7b d1 [2] 6f ca [2] 60 d0 [2] 7e cd [2] 7c cc [2] 67 ca [2] 7b cd [2] 67 e2 }

  condition:
    any of them
}