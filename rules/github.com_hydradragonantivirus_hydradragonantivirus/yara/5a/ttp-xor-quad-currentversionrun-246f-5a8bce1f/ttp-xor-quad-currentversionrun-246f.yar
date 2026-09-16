rule TTP_XOR_QUAD_CurrentVersionRun_246f {
  strings:
    $key_246f = { 77 00 [2] 53 0e [2] 78 22 [2] 56 00 [2] 42 1b [2] 4d 01 [2] 53 1c [2] 51 1d [2] 4a 1b [2] 56 1c [2] 4a 33 }

  condition:
    any of them
}