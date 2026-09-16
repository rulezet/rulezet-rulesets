rule TTP_XOR_QUAD_CurrentVersionRun_1e2a {
  strings:
    $key_1e2a = { 4d 45 [2] 69 4b [2] 42 67 [2] 6c 45 [2] 78 5e [2] 77 44 [2] 69 59 [2] 6b 58 [2] 70 5e [2] 6c 59 [2] 70 76 }

  condition:
    any of them
}