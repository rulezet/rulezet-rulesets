rule TTP_XOR_QUAD_CurrentVersionRun_b6be {
  strings:
    $key_b6be = { e5 d1 [2] c1 df [2] ea f3 [2] c4 d1 [2] d0 ca [2] df d0 [2] c1 cd [2] c3 cc [2] d8 ca [2] c4 cd [2] d8 e2 }

  condition:
    any of them
}