rule TTP_XOR_QUAD_CurrentVersionRun_0551 {
  strings:
    $key_0551 = { 56 3e [2] 72 30 [2] 59 1c [2] 77 3e [2] 63 25 [2] 6c 3f [2] 72 22 [2] 70 23 [2] 6b 25 [2] 77 22 [2] 6b 0d }

  condition:
    any of them
}