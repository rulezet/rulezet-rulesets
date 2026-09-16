rule TTP_XOR_QUAD_CurrentVersionRun_c0a3 {
  strings:
    $key_c0a3 = { 93 cc [2] b7 c2 [2] 9c ee [2] b2 cc [2] a6 d7 [2] a9 cd [2] b7 d0 [2] b5 d1 [2] ae d7 [2] b2 d0 [2] ae ff }

  condition:
    any of them
}