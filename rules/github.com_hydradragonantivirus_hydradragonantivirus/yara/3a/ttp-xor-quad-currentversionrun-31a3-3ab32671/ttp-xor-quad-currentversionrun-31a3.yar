rule TTP_XOR_QUAD_CurrentVersionRun_31a3 {
  strings:
    $key_31a3 = { 62 cc [2] 46 c2 [2] 6d ee [2] 43 cc [2] 57 d7 [2] 58 cd [2] 46 d0 [2] 44 d1 [2] 5f d7 [2] 43 d0 [2] 5f ff }

  condition:
    any of them
}