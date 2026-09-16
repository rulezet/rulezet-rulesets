rule TTP_XOR_QUAD_CurrentVersionRun_637f {
  strings:
    $key_637f = { 30 10 [2] 14 1e [2] 3f 32 [2] 11 10 [2] 05 0b [2] 0a 11 [2] 14 0c [2] 16 0d [2] 0d 0b [2] 11 0c [2] 0d 23 }

  condition:
    any of them
}