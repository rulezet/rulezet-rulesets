rule TTP_XOR_QUAD_CurrentVersionRun_2b4a {
  strings:
    $key_2b4a = { 78 25 [2] 5c 2b [2] 77 07 [2] 59 25 [2] 4d 3e [2] 42 24 [2] 5c 39 [2] 5e 38 [2] 45 3e [2] 59 39 [2] 45 16 }

  condition:
    any of them
}