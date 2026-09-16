rule TTP_XOR_QUAD_CurrentVersionRun_0521 {
  strings:
    $key_0521 = { 56 4e [2] 72 40 [2] 59 6c [2] 77 4e [2] 63 55 [2] 6c 4f [2] 72 52 [2] 70 53 [2] 6b 55 [2] 77 52 [2] 6b 7d }

  condition:
    any of them
}