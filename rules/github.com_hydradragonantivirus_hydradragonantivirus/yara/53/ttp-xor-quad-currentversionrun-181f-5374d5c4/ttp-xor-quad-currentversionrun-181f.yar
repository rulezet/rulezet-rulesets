rule TTP_XOR_QUAD_CurrentVersionRun_181f {
  strings:
    $key_181f = { 4b 70 [2] 6f 7e [2] 44 52 [2] 6a 70 [2] 7e 6b [2] 71 71 [2] 6f 6c [2] 6d 6d [2] 76 6b [2] 6a 6c [2] 76 43 }

  condition:
    any of them
}