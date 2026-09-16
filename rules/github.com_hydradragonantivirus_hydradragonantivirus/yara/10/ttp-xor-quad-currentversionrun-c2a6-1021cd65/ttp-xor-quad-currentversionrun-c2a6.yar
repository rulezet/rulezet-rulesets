rule TTP_XOR_QUAD_CurrentVersionRun_c2a6 {
  strings:
    $key_c2a6 = { 91 c9 [2] b5 c7 [2] 9e eb [2] b0 c9 [2] a4 d2 [2] ab c8 [2] b5 d5 [2] b7 d4 [2] ac d2 [2] b0 d5 [2] ac fa }

  condition:
    any of them
}