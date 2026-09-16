rule TTP_XOR_QUAD_CurrentVersionRun_1933 {
  strings:
    $key_1933 = { 4a 5c [2] 6e 52 [2] 45 7e [2] 6b 5c [2] 7f 47 [2] 70 5d [2] 6e 40 [2] 6c 41 [2] 77 47 [2] 6b 40 [2] 77 6f }

  condition:
    any of them
}