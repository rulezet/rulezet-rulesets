rule TTP_XOR_QUAD_CurrentVersionRun_3b1f {
  strings:
    $key_3b1f = { 68 70 [2] 4c 7e [2] 67 52 [2] 49 70 [2] 5d 6b [2] 52 71 [2] 4c 6c [2] 4e 6d [2] 55 6b [2] 49 6c [2] 55 43 }

  condition:
    any of them
}