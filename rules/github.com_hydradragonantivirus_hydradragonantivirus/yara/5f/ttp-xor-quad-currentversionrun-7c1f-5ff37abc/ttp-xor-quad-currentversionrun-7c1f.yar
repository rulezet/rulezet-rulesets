rule TTP_XOR_QUAD_CurrentVersionRun_7c1f {
  strings:
    $key_7c1f = { 2f 70 [2] 0b 7e [2] 20 52 [2] 0e 70 [2] 1a 6b [2] 15 71 [2] 0b 6c [2] 09 6d [2] 12 6b [2] 0e 6c [2] 12 43 }

  condition:
    any of them
}