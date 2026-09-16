rule TTP_XOR_QUAD_CurrentVersionRun_2d2f {
  strings:
    $key_2d2f = { 7e 40 [2] 5a 4e [2] 71 62 [2] 5f 40 [2] 4b 5b [2] 44 41 [2] 5a 5c [2] 58 5d [2] 43 5b [2] 5f 5c [2] 43 73 }

  condition:
    any of them
}