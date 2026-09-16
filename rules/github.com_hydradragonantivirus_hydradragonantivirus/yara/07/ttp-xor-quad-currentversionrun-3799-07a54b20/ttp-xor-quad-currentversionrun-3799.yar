rule TTP_XOR_QUAD_CurrentVersionRun_3799 {
  strings:
    $key_3799 = { 64 f6 [2] 40 f8 [2] 6b d4 [2] 45 f6 [2] 51 ed [2] 5e f7 [2] 40 ea [2] 42 eb [2] 59 ed [2] 45 ea [2] 59 c5 }

  condition:
    any of them
}