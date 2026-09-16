rule TTP_XOR_QUAD_CurrentVersionRun_196f {
  strings:
    $key_196f = { 4a 00 [2] 6e 0e [2] 45 22 [2] 6b 00 [2] 7f 1b [2] 70 01 [2] 6e 1c [2] 6c 1d [2] 77 1b [2] 6b 1c [2] 77 33 }

  condition:
    any of them
}