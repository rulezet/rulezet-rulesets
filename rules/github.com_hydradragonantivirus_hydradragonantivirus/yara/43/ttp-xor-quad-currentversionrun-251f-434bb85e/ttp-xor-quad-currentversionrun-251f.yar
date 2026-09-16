rule TTP_XOR_QUAD_CurrentVersionRun_251f {
  strings:
    $key_251f = { 76 70 [2] 52 7e [2] 79 52 [2] 57 70 [2] 43 6b [2] 4c 71 [2] 52 6c [2] 50 6d [2] 4b 6b [2] 57 6c [2] 4b 43 }

  condition:
    any of them
}