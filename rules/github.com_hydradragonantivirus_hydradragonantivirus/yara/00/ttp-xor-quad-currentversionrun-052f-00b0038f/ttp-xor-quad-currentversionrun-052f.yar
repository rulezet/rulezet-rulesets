rule TTP_XOR_QUAD_CurrentVersionRun_052f {
  strings:
    $key_052f = { 56 40 [2] 72 4e [2] 59 62 [2] 77 40 [2] 63 5b [2] 6c 41 [2] 72 5c [2] 70 5d [2] 6b 5b [2] 77 5c [2] 6b 73 }

  condition:
    any of them
}