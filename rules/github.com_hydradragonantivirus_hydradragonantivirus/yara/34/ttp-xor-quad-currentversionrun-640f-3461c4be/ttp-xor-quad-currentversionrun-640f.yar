rule TTP_XOR_QUAD_CurrentVersionRun_640f {
  strings:
    $key_640f = { 37 60 [2] 13 6e [2] 38 42 [2] 16 60 [2] 02 7b [2] 0d 61 [2] 13 7c [2] 11 7d [2] 0a 7b [2] 16 7c [2] 0a 53 }

  condition:
    any of them
}