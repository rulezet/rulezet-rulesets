rule TTP_XOR_QUAD_CurrentVersionRun_510f {
  strings:
    $key_510f = { 02 60 [2] 26 6e [2] 0d 42 [2] 23 60 [2] 37 7b [2] 38 61 [2] 26 7c [2] 24 7d [2] 3f 7b [2] 23 7c [2] 3f 53 }

  condition:
    any of them
}