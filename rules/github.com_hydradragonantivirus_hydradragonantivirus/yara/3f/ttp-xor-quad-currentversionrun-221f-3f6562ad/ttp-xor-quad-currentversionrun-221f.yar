rule TTP_XOR_QUAD_CurrentVersionRun_221f {
  strings:
    $key_221f = { 71 70 [2] 55 7e [2] 7e 52 [2] 50 70 [2] 44 6b [2] 4b 71 [2] 55 6c [2] 57 6d [2] 4c 6b [2] 50 6c [2] 4c 43 }

  condition:
    any of them
}