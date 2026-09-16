rule TTP_XOR_QUAD_CurrentVersionRun_20a3 {
  strings:
    $key_20a3 = { 73 cc [2] 57 c2 [2] 7c ee [2] 52 cc [2] 46 d7 [2] 49 cd [2] 57 d0 [2] 55 d1 [2] 4e d7 [2] 52 d0 [2] 4e ff }

  condition:
    any of them
}