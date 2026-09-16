rule TTP_XOR_QUAD_CurrentVersionRun_1f3f {
  strings:
    $key_1f3f = { 4c 50 [2] 68 5e [2] 43 72 [2] 6d 50 [2] 79 4b [2] 76 51 [2] 68 4c [2] 6a 4d [2] 71 4b [2] 6d 4c [2] 71 63 }

  condition:
    any of them
}