rule TTP_XOR_QUAD_CurrentVersionRun_19af {
  strings:
    $key_19af = { 4a c0 [2] 6e ce [2] 45 e2 [2] 6b c0 [2] 7f db [2] 70 c1 [2] 6e dc [2] 6c dd [2] 77 db [2] 6b dc [2] 77 f3 }

  condition:
    any of them
}