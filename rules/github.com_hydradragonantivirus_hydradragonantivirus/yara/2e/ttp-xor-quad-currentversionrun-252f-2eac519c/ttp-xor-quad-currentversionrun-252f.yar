rule TTP_XOR_QUAD_CurrentVersionRun_252f {
  strings:
    $key_252f = { 76 40 [2] 52 4e [2] 79 62 [2] 57 40 [2] 43 5b [2] 4c 41 [2] 52 5c [2] 50 5d [2] 4b 5b [2] 57 5c [2] 4b 73 }

  condition:
    any of them
}