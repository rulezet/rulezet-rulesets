rule TTP_XOR_QUAD_CurrentVersionRun_f784 {
  strings:
    $key_f784 = { a4 eb [2] 80 e5 [2] ab c9 [2] 85 eb [2] 91 f0 [2] 9e ea [2] 80 f7 [2] 82 f6 [2] 99 f0 [2] 85 f7 [2] 99 d8 }

  condition:
    any of them
}