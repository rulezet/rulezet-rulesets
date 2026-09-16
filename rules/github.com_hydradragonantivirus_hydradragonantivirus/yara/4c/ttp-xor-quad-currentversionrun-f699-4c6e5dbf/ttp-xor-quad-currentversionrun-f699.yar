rule TTP_XOR_QUAD_CurrentVersionRun_f699 {
  strings:
    $key_f699 = { a5 f6 [2] 81 f8 [2] aa d4 [2] 84 f6 [2] 90 ed [2] 9f f7 [2] 81 ea [2] 83 eb [2] 98 ed [2] 84 ea [2] 98 c5 }

  condition:
    any of them
}