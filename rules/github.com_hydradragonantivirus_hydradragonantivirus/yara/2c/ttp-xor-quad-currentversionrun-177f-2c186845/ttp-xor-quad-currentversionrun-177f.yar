rule TTP_XOR_QUAD_CurrentVersionRun_177f {
  strings:
    $key_177f = { 44 10 [2] 60 1e [2] 4b 32 [2] 65 10 [2] 71 0b [2] 7e 11 [2] 60 0c [2] 62 0d [2] 79 0b [2] 65 0c [2] 79 23 }

  condition:
    any of them
}