rule TTP_XOR_QUAD_CurrentVersionRun_deb4 {
  strings:
    $key_deb4 = { 8d db [2] a9 d5 [2] 82 f9 [2] ac db [2] b8 c0 [2] b7 da [2] a9 c7 [2] ab c6 [2] b0 c0 [2] ac c7 [2] b0 e8 }

  condition:
    any of them
}