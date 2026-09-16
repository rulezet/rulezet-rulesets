rule TTP_XOR_QUAD_CurrentVersionRun_4b2f {
  strings:
    $key_4b2f = { 18 40 [2] 3c 4e [2] 17 62 [2] 39 40 [2] 2d 5b [2] 22 41 [2] 3c 5c [2] 3e 5d [2] 25 5b [2] 39 5c [2] 25 73 }

  condition:
    any of them
}