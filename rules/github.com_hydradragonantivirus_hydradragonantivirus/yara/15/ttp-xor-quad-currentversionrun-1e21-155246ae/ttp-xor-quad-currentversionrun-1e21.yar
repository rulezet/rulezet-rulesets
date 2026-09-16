rule TTP_XOR_QUAD_CurrentVersionRun_1e21 {
  strings:
    $key_1e21 = { 4d 4e [2] 69 40 [2] 42 6c [2] 6c 4e [2] 78 55 [2] 77 4f [2] 69 52 [2] 6b 53 [2] 70 55 [2] 6c 52 [2] 70 7d }

  condition:
    any of them
}