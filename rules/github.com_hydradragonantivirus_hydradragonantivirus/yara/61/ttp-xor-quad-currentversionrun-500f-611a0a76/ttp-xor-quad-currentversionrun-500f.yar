rule TTP_XOR_QUAD_CurrentVersionRun_500f {
  strings:
    $key_500f = { 03 60 [2] 27 6e [2] 0c 42 [2] 22 60 [2] 36 7b [2] 39 61 [2] 27 7c [2] 25 7d [2] 3e 7b [2] 22 7c [2] 3e 53 }

  condition:
    any of them
}