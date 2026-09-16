rule TTP_XOR_QUAD_CurrentVersionRun_bcad {
  strings:
    $key_bcad = { ef c2 [2] cb cc [2] e0 e0 [2] ce c2 [2] da d9 [2] d5 c3 [2] cb de [2] c9 df [2] d2 d9 [2] ce de [2] d2 f1 }

  condition:
    any of them
}