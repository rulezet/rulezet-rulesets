rule TTP_XOR_QUAD_CurrentVersionRun_027d {
  strings:
    $key_027d = { 51 12 [2] 75 1c [2] 5e 30 [2] 70 12 [2] 64 09 [2] 6b 13 [2] 75 0e [2] 77 0f [2] 6c 09 [2] 70 0e [2] 6c 21 }

  condition:
    any of them
}