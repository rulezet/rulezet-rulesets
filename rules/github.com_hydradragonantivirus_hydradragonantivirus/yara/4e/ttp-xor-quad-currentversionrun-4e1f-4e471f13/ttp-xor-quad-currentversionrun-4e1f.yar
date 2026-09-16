rule TTP_XOR_QUAD_CurrentVersionRun_4e1f {
  strings:
    $key_4e1f = { 1d 70 [2] 39 7e [2] 12 52 [2] 3c 70 [2] 28 6b [2] 27 71 [2] 39 6c [2] 3b 6d [2] 20 6b [2] 3c 6c [2] 20 43 }

  condition:
    any of them
}