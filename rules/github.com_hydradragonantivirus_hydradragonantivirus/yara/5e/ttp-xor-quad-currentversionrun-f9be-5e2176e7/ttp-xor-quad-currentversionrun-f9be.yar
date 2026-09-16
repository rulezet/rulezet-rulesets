rule TTP_XOR_QUAD_CurrentVersionRun_f9be {
  strings:
    $key_f9be = { aa d1 [2] 8e df [2] a5 f3 [2] 8b d1 [2] 9f ca [2] 90 d0 [2] 8e cd [2] 8c cc [2] 97 ca [2] 8b cd [2] 97 e2 }

  condition:
    any of them
}