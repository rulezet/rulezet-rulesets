rule TTP_XOR_QUAD_CurrentVersionRun_5798 {
  strings:
    $key_5798 = { 04 f7 [2] 20 f9 [2] 0b d5 [2] 25 f7 [2] 31 ec [2] 3e f6 [2] 20 eb [2] 22 ea [2] 39 ec [2] 25 eb [2] 39 c4 }

  condition:
    any of them
}