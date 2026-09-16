rule TTP_XOR_QUAD_CurrentVersionRun_0c2f {
  strings:
    $key_0c2f = { 5f 40 [2] 7b 4e [2] 50 62 [2] 7e 40 [2] 6a 5b [2] 65 41 [2] 7b 5c [2] 79 5d [2] 62 5b [2] 7e 5c [2] 62 73 }

  condition:
    any of them
}