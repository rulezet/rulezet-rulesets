rule TTP_XOR_QUAD_CurrentVersionRun_1e0f {
  strings:
    $key_1e0f = { 4d 60 [2] 69 6e [2] 42 42 [2] 6c 60 [2] 78 7b [2] 77 61 [2] 69 7c [2] 6b 7d [2] 70 7b [2] 6c 7c [2] 70 53 }

  condition:
    any of them
}