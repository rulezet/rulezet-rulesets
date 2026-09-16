rule TTP_XOR_QUAD_CurrentVersionRun_033f {
  strings:
    $key_033f = { 50 50 [2] 74 5e [2] 5f 72 [2] 71 50 [2] 65 4b [2] 6a 51 [2] 74 4c [2] 76 4d [2] 6d 4b [2] 71 4c [2] 6d 63 }

  condition:
    any of them
}