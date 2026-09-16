rule TTP_XOR_QUAD_CurrentVersionRun_3a7f {
  strings:
    $key_3a7f = { 69 10 [2] 4d 1e [2] 66 32 [2] 48 10 [2] 5c 0b [2] 53 11 [2] 4d 0c [2] 4f 0d [2] 54 0b [2] 48 0c [2] 54 23 }

  condition:
    any of them
}