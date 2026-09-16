rule TTP_XOR_QUAD_CurrentVersionRun_702f {
  strings:
    $key_702f = { 23 40 [2] 07 4e [2] 2c 62 [2] 02 40 [2] 16 5b [2] 19 41 [2] 07 5c [2] 05 5d [2] 1e 5b [2] 02 5c [2] 1e 73 }

  condition:
    any of them
}