rule TTP_XOR_QUAD_CurrentVersionRun_7e2f {
  strings:
    $key_7e2f = { 2d 40 [2] 09 4e [2] 22 62 [2] 0c 40 [2] 18 5b [2] 17 41 [2] 09 5c [2] 0b 5d [2] 10 5b [2] 0c 5c [2] 10 73 }

  condition:
    any of them
}