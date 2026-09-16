rule TTP_XOR_QUAD_CurrentVersionRun_2b01 {
  strings:
    $key_2b01 = { 78 6e [2] 5c 60 [2] 77 4c [2] 59 6e [2] 4d 75 [2] 42 6f [2] 5c 72 [2] 5e 73 [2] 45 75 [2] 59 72 [2] 45 5d }

  condition:
    any of them
}