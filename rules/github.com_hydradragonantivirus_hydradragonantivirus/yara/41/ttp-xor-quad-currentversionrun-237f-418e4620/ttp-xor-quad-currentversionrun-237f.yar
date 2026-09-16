rule TTP_XOR_QUAD_CurrentVersionRun_237f {
  strings:
    $key_237f = { 70 10 [2] 54 1e [2] 7f 32 [2] 51 10 [2] 45 0b [2] 4a 11 [2] 54 0c [2] 56 0d [2] 4d 0b [2] 51 0c [2] 4d 23 }

  condition:
    any of them
}