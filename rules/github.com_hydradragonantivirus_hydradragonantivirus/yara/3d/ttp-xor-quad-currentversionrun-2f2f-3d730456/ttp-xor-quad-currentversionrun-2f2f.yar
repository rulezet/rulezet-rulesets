rule TTP_XOR_QUAD_CurrentVersionRun_2f2f {
  strings:
    $key_2f2f = { 7c 40 [2] 58 4e [2] 73 62 [2] 5d 40 [2] 49 5b [2] 46 41 [2] 58 5c [2] 5a 5d [2] 41 5b [2] 5d 5c [2] 41 73 }

  condition:
    any of them
}