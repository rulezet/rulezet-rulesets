rule TTP_XOR_QUAD_CurrentVersionRun_242f {
  strings:
    $key_242f = { 77 40 [2] 53 4e [2] 78 62 [2] 56 40 [2] 42 5b [2] 4d 41 [2] 53 5c [2] 51 5d [2] 4a 5b [2] 56 5c [2] 4a 73 }

  condition:
    any of them
}