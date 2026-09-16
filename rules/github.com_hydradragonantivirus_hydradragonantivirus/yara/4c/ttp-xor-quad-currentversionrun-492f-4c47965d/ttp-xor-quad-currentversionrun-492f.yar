rule TTP_XOR_QUAD_CurrentVersionRun_492f {
  strings:
    $key_492f = { 1a 40 [2] 3e 4e [2] 15 62 [2] 3b 40 [2] 2f 5b [2] 20 41 [2] 3e 5c [2] 3c 5d [2] 27 5b [2] 3b 5c [2] 27 73 }

  condition:
    any of them
}