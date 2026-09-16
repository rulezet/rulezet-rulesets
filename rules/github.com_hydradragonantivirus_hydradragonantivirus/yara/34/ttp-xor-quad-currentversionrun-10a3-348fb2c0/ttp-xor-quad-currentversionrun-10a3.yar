rule TTP_XOR_QUAD_CurrentVersionRun_10a3 {
  strings:
    $key_10a3 = { 43 cc [2] 67 c2 [2] 4c ee [2] 62 cc [2] 76 d7 [2] 79 cd [2] 67 d0 [2] 65 d1 [2] 7e d7 [2] 62 d0 [2] 7e ff }

  condition:
    any of them
}