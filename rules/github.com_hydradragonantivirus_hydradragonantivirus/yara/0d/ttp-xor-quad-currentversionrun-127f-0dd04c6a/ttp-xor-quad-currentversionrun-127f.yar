rule TTP_XOR_QUAD_CurrentVersionRun_127f {
  strings:
    $key_127f = { 41 10 [2] 65 1e [2] 4e 32 [2] 60 10 [2] 74 0b [2] 7b 11 [2] 65 0c [2] 67 0d [2] 7c 0b [2] 60 0c [2] 7c 23 }

  condition:
    any of them
}