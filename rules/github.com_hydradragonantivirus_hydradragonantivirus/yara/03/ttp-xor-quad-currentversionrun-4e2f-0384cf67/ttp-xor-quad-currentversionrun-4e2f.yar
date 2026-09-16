rule TTP_XOR_QUAD_CurrentVersionRun_4e2f {
  strings:
    $key_4e2f = { 1d 40 [2] 39 4e [2] 12 62 [2] 3c 40 [2] 28 5b [2] 27 41 [2] 39 5c [2] 3b 5d [2] 20 5b [2] 3c 5c [2] 20 73 }

  condition:
    any of them
}