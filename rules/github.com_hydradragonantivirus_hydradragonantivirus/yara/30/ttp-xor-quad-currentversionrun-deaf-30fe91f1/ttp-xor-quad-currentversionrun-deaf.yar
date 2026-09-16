rule TTP_XOR_QUAD_CurrentVersionRun_deaf {
  strings:
    $key_deaf = { 8d c0 [2] a9 ce [2] 82 e2 [2] ac c0 [2] b8 db [2] b7 c1 [2] a9 dc [2] ab dd [2] b0 db [2] ac dc [2] b0 f3 }

  condition:
    any of them
}