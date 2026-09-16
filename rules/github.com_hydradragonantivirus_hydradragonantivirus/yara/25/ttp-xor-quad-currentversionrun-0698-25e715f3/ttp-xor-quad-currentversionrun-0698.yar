rule TTP_XOR_QUAD_CurrentVersionRun_0698 {
  strings:
    $key_0698 = { 55 f7 [2] 71 f9 [2] 5a d5 [2] 74 f7 [2] 60 ec [2] 6f f6 [2] 71 eb [2] 73 ea [2] 68 ec [2] 74 eb [2] 68 c4 }

  condition:
    any of them
}