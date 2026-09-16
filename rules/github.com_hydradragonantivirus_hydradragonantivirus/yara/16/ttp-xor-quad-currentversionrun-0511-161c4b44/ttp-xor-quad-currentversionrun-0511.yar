rule TTP_XOR_QUAD_CurrentVersionRun_0511 {
  strings:
    $key_0511 = { 56 7e [2] 72 70 [2] 59 5c [2] 77 7e [2] 63 65 [2] 6c 7f [2] 72 62 [2] 70 63 [2] 6b 65 [2] 77 62 [2] 6b 4d }

  condition:
    any of them
}