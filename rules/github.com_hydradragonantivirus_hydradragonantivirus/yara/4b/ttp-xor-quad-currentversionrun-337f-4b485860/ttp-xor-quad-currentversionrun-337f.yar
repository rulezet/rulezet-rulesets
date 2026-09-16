rule TTP_XOR_QUAD_CurrentVersionRun_337f {
  strings:
    $key_337f = { 60 10 [2] 44 1e [2] 6f 32 [2] 41 10 [2] 55 0b [2] 5a 11 [2] 44 0c [2] 46 0d [2] 5d 0b [2] 41 0c [2] 5d 23 }

  condition:
    any of them
}