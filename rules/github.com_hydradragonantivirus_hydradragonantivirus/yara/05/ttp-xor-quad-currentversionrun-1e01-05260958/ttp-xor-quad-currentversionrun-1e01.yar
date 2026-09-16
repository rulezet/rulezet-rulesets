rule TTP_XOR_QUAD_CurrentVersionRun_1e01 {
  strings:
    $key_1e01 = { 4d 6e [2] 69 60 [2] 42 4c [2] 6c 6e [2] 78 75 [2] 77 6f [2] 69 72 [2] 6b 73 [2] 70 75 [2] 6c 72 [2] 70 5d }

  condition:
    any of them
}