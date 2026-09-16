rule TTP_XOR_QUAD_CurrentVersionRun_0562 {
  strings:
    $key_0562 = { 56 0d [2] 72 03 [2] 59 2f [2] 77 0d [2] 63 16 [2] 6c 0c [2] 72 11 [2] 70 10 [2] 6b 16 [2] 77 11 [2] 6b 3e }

  condition:
    any of them
}