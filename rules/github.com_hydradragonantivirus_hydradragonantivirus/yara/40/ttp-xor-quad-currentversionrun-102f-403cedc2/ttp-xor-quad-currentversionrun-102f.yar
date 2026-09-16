rule TTP_XOR_QUAD_CurrentVersionRun_102f {
  strings:
    $key_102f = { 43 40 [2] 67 4e [2] 4c 62 [2] 62 40 [2] 76 5b [2] 79 41 [2] 67 5c [2] 65 5d [2] 7e 5b [2] 62 5c [2] 7e 73 }

  condition:
    any of them
}