rule TTP_XOR_QUAD_CurrentVersionRun_1e0c {
  strings:
    $key_1e0c = { 4d 63 [2] 69 6d [2] 42 41 [2] 6c 63 [2] 78 78 [2] 77 62 [2] 69 7f [2] 6b 7e [2] 70 78 [2] 6c 7f [2] 70 50 }

  condition:
    any of them
}