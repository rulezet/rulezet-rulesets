rule TTP_XOR_QUAD_CurrentVersionRun_e099 {
  strings:
    $key_e099 = { b3 f6 [2] 97 f8 [2] bc d4 [2] 92 f6 [2] 86 ed [2] 89 f7 [2] 97 ea [2] 95 eb [2] 8e ed [2] 92 ea [2] 8e c5 }

  condition:
    any of them
}