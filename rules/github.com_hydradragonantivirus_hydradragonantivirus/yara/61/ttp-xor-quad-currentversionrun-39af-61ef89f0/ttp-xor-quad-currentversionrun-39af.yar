rule TTP_XOR_QUAD_CurrentVersionRun_39af {
  strings:
    $key_39af = { 6a c0 [2] 4e ce [2] 65 e2 [2] 4b c0 [2] 5f db [2] 50 c1 [2] 4e dc [2] 4c dd [2] 57 db [2] 4b dc [2] 57 f3 }

  condition:
    any of them
}