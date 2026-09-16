rule TTP_XOR_QUAD_CurrentVersionRun_002d {
  strings:
    $key_002d = { 53 42 [2] 77 4c [2] 5c 60 [2] 72 42 [2] 66 59 [2] 69 43 [2] 77 5e [2] 75 5f [2] 6e 59 [2] 72 5e [2] 6e 71 }

  condition:
    any of them
}