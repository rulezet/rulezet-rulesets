rule TTP_XOR_QUAD_CurrentVersionRun_beac {
  strings:
    $key_beac = { ed c3 [2] c9 cd [2] e2 e1 [2] cc c3 [2] d8 d8 [2] d7 c2 [2] c9 df [2] cb de [2] d0 d8 [2] cc df [2] d0 f0 }

  condition:
    any of them
}