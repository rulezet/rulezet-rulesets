rule TTP_XOR_QUAD_CurrentVersionRun_2699 {
  strings:
    $key_2699 = { 75 f6 [2] 51 f8 [2] 7a d4 [2] 54 f6 [2] 40 ed [2] 4f f7 [2] 51 ea [2] 53 eb [2] 48 ed [2] 54 ea [2] 48 c5 }

  condition:
    any of them
}