rule TTP_XOR_QUAD_CurrentVersionRun_09af {
  strings:
    $key_09af = { 5a c0 [2] 7e ce [2] 55 e2 [2] 7b c0 [2] 6f db [2] 60 c1 [2] 7e dc [2] 7c dd [2] 67 db [2] 7b dc [2] 67 f3 }

  condition:
    any of them
}