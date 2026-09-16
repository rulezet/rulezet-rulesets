rule TTP_XOR_QUAD_CurrentVersionRun_3484 {
  strings:
    $key_3484 = { 67 eb [2] 43 e5 [2] 68 c9 [2] 46 eb [2] 52 f0 [2] 5d ea [2] 43 f7 [2] 41 f6 [2] 5a f0 [2] 46 f7 [2] 5a d8 }

  condition:
    any of them
}