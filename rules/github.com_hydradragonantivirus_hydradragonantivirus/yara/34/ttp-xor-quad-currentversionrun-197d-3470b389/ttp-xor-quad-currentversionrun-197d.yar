rule TTP_XOR_QUAD_CurrentVersionRun_197d {
  strings:
    $key_197d = { 4a 12 [2] 6e 1c [2] 45 30 [2] 6b 12 [2] 7f 09 [2] 70 13 [2] 6e 0e [2] 6c 0f [2] 77 09 [2] 6b 0e [2] 77 21 }

  condition:
    any of them
}