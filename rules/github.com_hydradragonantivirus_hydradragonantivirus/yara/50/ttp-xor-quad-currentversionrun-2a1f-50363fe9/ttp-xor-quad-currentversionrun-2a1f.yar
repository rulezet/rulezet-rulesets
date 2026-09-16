rule TTP_XOR_QUAD_CurrentVersionRun_2a1f {
  strings:
    $key_2a1f = { 79 70 [2] 5d 7e [2] 76 52 [2] 58 70 [2] 4c 6b [2] 43 71 [2] 5d 6c [2] 5f 6d [2] 44 6b [2] 58 6c [2] 44 43 }

  condition:
    any of them
}