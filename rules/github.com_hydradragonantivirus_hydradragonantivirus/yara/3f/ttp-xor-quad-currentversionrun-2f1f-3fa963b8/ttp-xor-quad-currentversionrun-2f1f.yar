rule TTP_XOR_QUAD_CurrentVersionRun_2f1f {
  strings:
    $key_2f1f = { 7c 70 [2] 58 7e [2] 73 52 [2] 5d 70 [2] 49 6b [2] 46 71 [2] 58 6c [2] 5a 6d [2] 41 6b [2] 5d 6c [2] 41 43 }

  condition:
    any of them
}