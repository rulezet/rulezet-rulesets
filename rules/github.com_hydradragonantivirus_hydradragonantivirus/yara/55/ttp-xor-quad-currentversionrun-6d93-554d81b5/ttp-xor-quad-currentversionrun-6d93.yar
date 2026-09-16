rule TTP_XOR_QUAD_CurrentVersionRun_6d93 {
  strings:
    $key_6d93 = { 3e fc [2] 1a f2 [2] 31 de [2] 1f fc [2] 0b e7 [2] 04 fd [2] 1a e0 [2] 18 e1 [2] 03 e7 [2] 1f e0 [2] 03 cf }

  condition:
    any of them
}