rule TTP_XOR_QUAD_CurrentVersionRun_240f {
  strings:
    $key_240f = { 77 60 [2] 53 6e [2] 78 42 [2] 56 60 [2] 42 7b [2] 4d 61 [2] 53 7c [2] 51 7d [2] 4a 7b [2] 56 7c [2] 4a 53 }

  condition:
    any of them
}