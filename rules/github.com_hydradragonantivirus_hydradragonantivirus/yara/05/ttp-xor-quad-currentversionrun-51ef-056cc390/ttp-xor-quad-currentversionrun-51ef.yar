rule TTP_XOR_QUAD_CurrentVersionRun_51ef {
  strings:
    $key_51ef = { 02 80 [2] 26 8e [2] 0d a2 [2] 23 80 [2] 37 9b [2] 38 81 [2] 26 9c [2] 24 9d [2] 3f 9b [2] 23 9c [2] 3f b3 }

  condition:
    any of them
}