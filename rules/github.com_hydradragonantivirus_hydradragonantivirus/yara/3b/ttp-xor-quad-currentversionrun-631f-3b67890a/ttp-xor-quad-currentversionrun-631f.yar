rule TTP_XOR_QUAD_CurrentVersionRun_631f {
  strings:
    $key_631f = { 30 70 [2] 14 7e [2] 3f 52 [2] 11 70 [2] 05 6b [2] 0a 71 [2] 14 6c [2] 16 6d [2] 0d 6b [2] 11 6c [2] 0d 43 }

  condition:
    any of them
}