rule TTP_XOR_QUAD_CurrentVersionRun_247f {
  strings:
    $key_247f = { 77 10 [2] 53 1e [2] 78 32 [2] 56 10 [2] 42 0b [2] 4d 11 [2] 53 0c [2] 51 0d [2] 4a 0b [2] 56 0c [2] 4a 23 }

  condition:
    any of them
}