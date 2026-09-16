rule TTP_XOR_QUAD_CurrentVersionRun_98b1 {
  strings:
    $key_98b1 = { cb de [2] ef d0 [2] c4 fc [2] ea de [2] fe c5 [2] f1 df [2] ef c2 [2] ed c3 [2] f6 c5 [2] ea c2 [2] f6 ed }

  condition:
    any of them
}