rule TTP_XOR_QUAD_CurrentVersionRun_222f {
  strings:
    $key_222f = { 71 40 [2] 55 4e [2] 7e 62 [2] 50 40 [2] 44 5b [2] 4b 41 [2] 55 5c [2] 57 5d [2] 4c 5b [2] 50 5c [2] 4c 73 }

  condition:
    any of them
}