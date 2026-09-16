rule TTP_XOR_QUAD_CurrentVersionRun_360f {
  strings:
    $key_360f = { 65 60 [2] 41 6e [2] 6a 42 [2] 44 60 [2] 50 7b [2] 5f 61 [2] 41 7c [2] 43 7d [2] 58 7b [2] 44 7c [2] 58 53 }

  condition:
    any of them
}