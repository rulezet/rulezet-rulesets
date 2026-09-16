rule TTP_XOR_QUAD_CurrentVersionRun_561f {
  strings:
    $key_561f = { 05 70 [2] 21 7e [2] 0a 52 [2] 24 70 [2] 30 6b [2] 3f 71 [2] 21 6c [2] 23 6d [2] 38 6b [2] 24 6c [2] 38 43 }

  condition:
    any of them
}