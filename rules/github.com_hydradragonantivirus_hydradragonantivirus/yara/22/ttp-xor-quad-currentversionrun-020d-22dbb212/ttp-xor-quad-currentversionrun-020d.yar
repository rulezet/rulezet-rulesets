rule TTP_XOR_QUAD_CurrentVersionRun_020d {
  strings:
    $key_020d = { 51 62 [2] 75 6c [2] 5e 40 [2] 70 62 [2] 64 79 [2] 6b 63 [2] 75 7e [2] 77 7f [2] 6c 79 [2] 70 7e [2] 6c 51 }

  condition:
    any of them
}