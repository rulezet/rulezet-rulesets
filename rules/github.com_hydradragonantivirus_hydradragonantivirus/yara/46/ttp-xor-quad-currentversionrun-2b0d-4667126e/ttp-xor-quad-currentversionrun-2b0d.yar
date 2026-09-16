rule TTP_XOR_QUAD_CurrentVersionRun_2b0d {
  strings:
    $key_2b0d = { 78 62 [2] 5c 6c [2] 77 40 [2] 59 62 [2] 4d 79 [2] 42 63 [2] 5c 7e [2] 5e 7f [2] 45 79 [2] 59 7e [2] 45 51 }

  condition:
    any of them
}