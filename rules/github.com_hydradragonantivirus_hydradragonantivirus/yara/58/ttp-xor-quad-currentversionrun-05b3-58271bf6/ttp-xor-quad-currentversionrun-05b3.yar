rule TTP_XOR_QUAD_CurrentVersionRun_05b3 {
  strings:
    $key_05b3 = { 56 dc [2] 72 d2 [2] 59 fe [2] 77 dc [2] 63 c7 [2] 6c dd [2] 72 c0 [2] 70 c1 [2] 6b c7 [2] 77 c0 [2] 6b ef }

  condition:
    any of them
}