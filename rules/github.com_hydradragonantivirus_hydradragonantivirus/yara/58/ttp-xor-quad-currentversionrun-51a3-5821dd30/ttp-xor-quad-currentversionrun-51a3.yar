rule TTP_XOR_QUAD_CurrentVersionRun_51a3 {
  strings:
    $key_51a3 = { 02 cc [2] 26 c2 [2] 0d ee [2] 23 cc [2] 37 d7 [2] 38 cd [2] 26 d0 [2] 24 d1 [2] 3f d7 [2] 23 d0 [2] 3f ff }

  condition:
    any of them
}