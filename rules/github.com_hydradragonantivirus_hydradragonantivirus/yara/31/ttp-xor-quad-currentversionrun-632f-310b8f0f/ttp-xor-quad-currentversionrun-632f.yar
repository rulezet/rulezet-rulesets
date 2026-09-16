rule TTP_XOR_QUAD_CurrentVersionRun_632f {
  strings:
    $key_632f = { 30 40 [2] 14 4e [2] 3f 62 [2] 11 40 [2] 05 5b [2] 0a 41 [2] 14 5c [2] 16 5d [2] 0d 5b [2] 11 5c [2] 0d 73 }

  condition:
    any of them
}