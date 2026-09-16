rule TTP_XOR_QUAD_CurrentVersionRun_040f {
  strings:
    $key_040f = { 57 60 [2] 73 6e [2] 58 42 [2] 76 60 [2] 62 7b [2] 6d 61 [2] 73 7c [2] 71 7d [2] 6a 7b [2] 76 7c [2] 6a 53 }

  condition:
    any of them
}