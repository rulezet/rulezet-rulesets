rule TTP_XOR_QUAD_CurrentVersionRun_297f {
  strings:
    $key_297f = { 7a 10 [2] 5e 1e [2] 75 32 [2] 5b 10 [2] 4f 0b [2] 40 11 [2] 5e 0c [2] 5c 0d [2] 47 0b [2] 5b 0c [2] 47 23 }

  condition:
    any of them
}