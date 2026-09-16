rule TTP_XOR_QUAD_CurrentVersionRun_3f5a {
  strings:
    $key_3f5a = { 6c 35 [2] 48 3b [2] 63 17 [2] 4d 35 [2] 59 2e [2] 56 34 [2] 48 29 [2] 4a 28 [2] 51 2e [2] 4d 29 [2] 51 06 }

  condition:
    any of them
}