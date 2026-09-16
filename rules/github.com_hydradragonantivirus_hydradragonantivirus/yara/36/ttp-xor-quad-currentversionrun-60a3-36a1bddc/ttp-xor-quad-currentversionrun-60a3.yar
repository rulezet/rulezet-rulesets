rule TTP_XOR_QUAD_CurrentVersionRun_60a3 {
  strings:
    $key_60a3 = { 33 cc [2] 17 c2 [2] 3c ee [2] 12 cc [2] 06 d7 [2] 09 cd [2] 17 d0 [2] 15 d1 [2] 0e d7 [2] 12 d0 [2] 0e ff }

  condition:
    any of them
}