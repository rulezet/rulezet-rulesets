rule TTP_XOR_QUAD_CurrentVersionRun_2b51 {
  strings:
    $key_2b51 = { 78 3e [2] 5c 30 [2] 77 1c [2] 59 3e [2] 4d 25 [2] 42 3f [2] 5c 22 [2] 5e 23 [2] 45 25 [2] 59 22 [2] 45 0d }

  condition:
    any of them
}