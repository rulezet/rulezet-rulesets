rule TTP_XOR_QUAD_CurrentVersionRun_055a {
  strings:
    $key_055a = { 56 35 [2] 72 3b [2] 59 17 [2] 77 35 [2] 63 2e [2] 6c 34 [2] 72 29 [2] 70 28 [2] 6b 2e [2] 77 29 [2] 6b 06 }

  condition:
    any of them
}