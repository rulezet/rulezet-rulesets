rule TTP_XOR_QUAD_CurrentVersionRun_0593 {
  strings:
    $key_0593 = { 56 fc [2] 72 f2 [2] 59 de [2] 77 fc [2] 63 e7 [2] 6c fd [2] 72 e0 [2] 70 e1 [2] 6b e7 [2] 77 e0 [2] 6b cf }

  condition:
    any of them
}