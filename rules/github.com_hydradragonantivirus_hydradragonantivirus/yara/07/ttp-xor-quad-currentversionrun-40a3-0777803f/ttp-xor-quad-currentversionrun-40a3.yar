rule TTP_XOR_QUAD_CurrentVersionRun_40a3 {
  strings:
    $key_40a3 = { 13 cc [2] 37 c2 [2] 1c ee [2] 32 cc [2] 26 d7 [2] 29 cd [2] 37 d0 [2] 35 d1 [2] 2e d7 [2] 32 d0 [2] 2e ff }

  condition:
    any of them
}