rule TTP_XOR_QUAD_CurrentVersionRun_551f {
  strings:
    $key_551f = { 06 70 [2] 22 7e [2] 09 52 [2] 27 70 [2] 33 6b [2] 3c 71 [2] 22 6c [2] 20 6d [2] 3b 6b [2] 27 6c [2] 3b 43 }

  condition:
    any of them
}