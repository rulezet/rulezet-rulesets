rule TTP_XOR_QUAD_CurrentVersionRun_1e1f {
  strings:
    $key_1e1f = { 4d 70 [2] 69 7e [2] 42 52 [2] 6c 70 [2] 78 6b [2] 77 71 [2] 69 6c [2] 6b 6d [2] 70 6b [2] 6c 6c [2] 70 43 }

  condition:
    any of them
}