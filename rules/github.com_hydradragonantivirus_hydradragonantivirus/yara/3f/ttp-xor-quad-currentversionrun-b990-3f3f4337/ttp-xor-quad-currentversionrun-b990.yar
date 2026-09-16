rule TTP_XOR_QUAD_CurrentVersionRun_b990 {
  strings:
    $key_b990 = { ea ff [2] ce f1 [2] e5 dd [2] cb ff [2] df e4 [2] d0 fe [2] ce e3 [2] cc e2 [2] d7 e4 [2] cb e3 [2] d7 cc }

  condition:
    any of them
}