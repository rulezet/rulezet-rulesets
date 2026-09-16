rule TTP_XOR_QUAD_CurrentVersionRun_7e7f {
  strings:
    $key_7e7f = { 2d 10 [2] 09 1e [2] 22 32 [2] 0c 10 [2] 18 0b [2] 17 11 [2] 09 0c [2] 0b 0d [2] 10 0b [2] 0c 0c [2] 10 23 }

  condition:
    any of them
}