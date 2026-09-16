rule TTP_XOR_QUAD_CurrentVersionRun_0526 {
  strings:
    $key_0526 = { 56 49 [2] 72 47 [2] 59 6b [2] 77 49 [2] 63 52 [2] 6c 48 [2] 72 55 [2] 70 54 [2] 6b 52 [2] 77 55 [2] 6b 7a }

  condition:
    any of them
}