rule TTP_XOR_QUAD_CurrentVersionRun_3b7f {
  strings:
    $key_3b7f = { 68 10 [2] 4c 1e [2] 67 32 [2] 49 10 [2] 5d 0b [2] 52 11 [2] 4c 0c [2] 4e 0d [2] 55 0b [2] 49 0c [2] 55 23 }

  condition:
    any of them
}