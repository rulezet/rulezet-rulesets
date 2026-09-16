rule TTP_XOR_QUAD_CurrentVersionRun_da98 {
  strings:
    $key_da98 = { 89 f7 [2] ad f9 [2] 86 d5 [2] a8 f7 [2] bc ec [2] b3 f6 [2] ad eb [2] af ea [2] b4 ec [2] a8 eb [2] b4 c4 }

  condition:
    any of them
}