rule TTP_XOR_QUAD_CurrentVersionRun_691f {
  strings:
    $key_691f = { 3a 70 [2] 1e 7e [2] 35 52 [2] 1b 70 [2] 0f 6b [2] 00 71 [2] 1e 6c [2] 1c 6d [2] 07 6b [2] 1b 6c [2] 07 43 }

  condition:
    any of them
}