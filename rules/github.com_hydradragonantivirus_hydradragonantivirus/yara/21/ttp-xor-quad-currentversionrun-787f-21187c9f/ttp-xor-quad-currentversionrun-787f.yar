rule TTP_XOR_QUAD_CurrentVersionRun_787f {
  strings:
    $key_787f = { 2b 10 [2] 0f 1e [2] 24 32 [2] 0a 10 [2] 1e 0b [2] 11 11 [2] 0f 0c [2] 0d 0d [2] 16 0b [2] 0a 0c [2] 16 23 }

  condition:
    any of them
}