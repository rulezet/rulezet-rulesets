rule TTP_XOR_QUAD_CurrentVersionRun_0572 {
  strings:
    $key_0572 = { 56 1d [2] 72 13 [2] 59 3f [2] 77 1d [2] 63 06 [2] 6c 1c [2] 72 01 [2] 70 00 [2] 6b 06 [2] 77 01 [2] 6b 2e }

  condition:
    any of them
}