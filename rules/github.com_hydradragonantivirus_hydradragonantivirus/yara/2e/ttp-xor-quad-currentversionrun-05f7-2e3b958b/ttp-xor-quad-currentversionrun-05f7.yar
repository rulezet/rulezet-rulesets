rule TTP_XOR_QUAD_CurrentVersionRun_05f7 {
  strings:
    $key_05f7 = { 56 98 [2] 72 96 [2] 59 ba [2] 77 98 [2] 63 83 [2] 6c 99 [2] 72 84 [2] 70 85 [2] 6b 83 [2] 77 84 [2] 6b ab }

  condition:
    any of them
}