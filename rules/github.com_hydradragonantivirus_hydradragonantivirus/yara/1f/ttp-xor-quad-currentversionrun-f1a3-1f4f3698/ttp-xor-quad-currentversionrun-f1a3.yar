rule TTP_XOR_QUAD_CurrentVersionRun_f1a3 {
  strings:
    $key_f1a3 = { a2 cc [2] 86 c2 [2] ad ee [2] 83 cc [2] 97 d7 [2] 98 cd [2] 86 d0 [2] 84 d1 [2] 9f d7 [2] 83 d0 [2] 9f ff }

  condition:
    any of them
}