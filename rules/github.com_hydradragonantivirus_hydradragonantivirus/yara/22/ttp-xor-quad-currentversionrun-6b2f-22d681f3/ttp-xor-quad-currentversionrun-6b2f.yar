rule TTP_XOR_QUAD_CurrentVersionRun_6b2f {
  strings:
    $key_6b2f = { 38 40 [2] 1c 4e [2] 37 62 [2] 19 40 [2] 0d 5b [2] 02 41 [2] 1c 5c [2] 1e 5d [2] 05 5b [2] 19 5c [2] 05 73 }

  condition:
    any of them
}