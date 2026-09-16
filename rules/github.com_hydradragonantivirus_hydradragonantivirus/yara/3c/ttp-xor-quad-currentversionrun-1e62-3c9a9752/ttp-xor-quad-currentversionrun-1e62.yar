rule TTP_XOR_QUAD_CurrentVersionRun_1e62 {
  strings:
    $key_1e62 = { 4d 0d [2] 69 03 [2] 42 2f [2] 6c 0d [2] 78 16 [2] 77 0c [2] 69 11 [2] 6b 10 [2] 70 16 [2] 6c 11 [2] 70 3e }

  condition:
    any of them
}