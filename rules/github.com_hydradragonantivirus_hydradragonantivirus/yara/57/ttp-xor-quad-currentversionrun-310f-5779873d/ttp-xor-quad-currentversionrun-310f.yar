rule TTP_XOR_QUAD_CurrentVersionRun_310f {
  strings:
    $key_310f = { 62 60 [2] 46 6e [2] 6d 42 [2] 43 60 [2] 57 7b [2] 58 61 [2] 46 7c [2] 44 7d [2] 5f 7b [2] 43 7c [2] 5f 53 }

  condition:
    any of them
}