rule TTP_XOR_QUAD_CurrentVersionRun_292f {
  strings:
    $key_292f = { 7a 40 [2] 5e 4e [2] 75 62 [2] 5b 40 [2] 4f 5b [2] 40 41 [2] 5e 5c [2] 5c 5d [2] 47 5b [2] 5b 5c [2] 47 73 }

  condition:
    any of them
}