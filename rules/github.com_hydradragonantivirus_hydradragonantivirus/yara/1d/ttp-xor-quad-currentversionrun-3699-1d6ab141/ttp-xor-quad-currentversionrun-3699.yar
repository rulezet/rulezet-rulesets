rule TTP_XOR_QUAD_CurrentVersionRun_3699 {
  strings:
    $key_3699 = { 65 f6 [2] 41 f8 [2] 6a d4 [2] 44 f6 [2] 50 ed [2] 5f f7 [2] 41 ea [2] 43 eb [2] 58 ed [2] 44 ea [2] 58 c5 }

  condition:
    any of them
}