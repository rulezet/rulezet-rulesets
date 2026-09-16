rule TTP_XOR_QUAD_CurrentVersionRun_b9af {
  strings:
    $key_b9af = { ea c0 [2] ce ce [2] e5 e2 [2] cb c0 [2] df db [2] d0 c1 [2] ce dc [2] cc dd [2] d7 db [2] cb dc [2] d7 f3 }

  condition:
    any of them
}