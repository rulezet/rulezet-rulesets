rule TTP_XOR_QUAD_CurrentVersionRun_6698 {
  strings:
    $key_6698 = { 35 f7 [2] 11 f9 [2] 3a d5 [2] 14 f7 [2] 00 ec [2] 0f f6 [2] 11 eb [2] 13 ea [2] 08 ec [2] 14 eb [2] 08 c4 }

  condition:
    any of them
}