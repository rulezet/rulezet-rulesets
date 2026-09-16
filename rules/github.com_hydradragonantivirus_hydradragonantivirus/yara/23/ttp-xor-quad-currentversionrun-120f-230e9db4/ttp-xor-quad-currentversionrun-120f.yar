rule TTP_XOR_QUAD_CurrentVersionRun_120f {
  strings:
    $key_120f = { 41 60 [2] 65 6e [2] 4e 42 [2] 60 60 [2] 74 7b [2] 7b 61 [2] 65 7c [2] 67 7d [2] 7c 7b [2] 60 7c [2] 7c 53 }

  condition:
    any of them
}