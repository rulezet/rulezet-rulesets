rule TTP_XOR_QUAD_CurrentVersionRun_1e3c {
  strings:
    $key_1e3c = { 4d 53 [2] 69 5d [2] 42 71 [2] 6c 53 [2] 78 48 [2] 77 52 [2] 69 4f [2] 6b 4e [2] 70 48 [2] 6c 4f [2] 70 60 }

  condition:
    any of them
}