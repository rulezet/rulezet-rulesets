rule TTP_XOR_QUAD_CurrentVersionRun_b9be {
  strings:
    $key_b9be = { ea d1 [2] ce df [2] e5 f3 [2] cb d1 [2] df ca [2] d0 d0 [2] ce cd [2] cc cc [2] d7 ca [2] cb cd [2] d7 e2 }

  condition:
    any of them
}