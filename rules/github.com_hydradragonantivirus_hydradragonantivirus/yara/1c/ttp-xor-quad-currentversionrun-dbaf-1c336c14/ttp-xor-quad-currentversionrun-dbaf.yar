rule TTP_XOR_QUAD_CurrentVersionRun_dbaf {
  strings:
    $key_dbaf = { 88 c0 [2] ac ce [2] 87 e2 [2] a9 c0 [2] bd db [2] b2 c1 [2] ac dc [2] ae dd [2] b5 db [2] a9 dc [2] b5 f3 }

  condition:
    any of them
}