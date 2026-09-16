rule TTP_XOR_QUAD_CurrentVersionRun_0e1f {
  strings:
    $key_0e1f = { 5d 70 [2] 79 7e [2] 52 52 [2] 7c 70 [2] 68 6b [2] 67 71 [2] 79 6c [2] 7b 6d [2] 60 6b [2] 7c 6c [2] 60 43 }

  condition:
    any of them
}