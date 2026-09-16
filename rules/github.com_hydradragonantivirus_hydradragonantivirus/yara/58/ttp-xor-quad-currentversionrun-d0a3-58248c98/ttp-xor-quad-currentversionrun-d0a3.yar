rule TTP_XOR_QUAD_CurrentVersionRun_d0a3 {
  strings:
    $key_d0a3 = { 83 cc [2] a7 c2 [2] 8c ee [2] a2 cc [2] b6 d7 [2] b9 cd [2] a7 d0 [2] a5 d1 [2] be d7 [2] a2 d0 [2] be ff }

  condition:
    any of them
}