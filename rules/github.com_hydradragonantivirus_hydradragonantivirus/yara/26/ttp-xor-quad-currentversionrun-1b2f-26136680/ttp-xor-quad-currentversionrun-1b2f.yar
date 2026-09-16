rule TTP_XOR_QUAD_CurrentVersionRun_1b2f {
  strings:
    $key_1b2f = { 48 40 [2] 6c 4e [2] 47 62 [2] 69 40 [2] 7d 5b [2] 72 41 [2] 6c 5c [2] 6e 5d [2] 75 5b [2] 69 5c [2] 75 73 }

  condition:
    any of them
}