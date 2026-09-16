rule TTP_XOR_QUAD_CurrentVersionRun_0f0f {
  strings:
    $key_0f0f = { 5c 60 [2] 78 6e [2] 53 42 [2] 7d 60 [2] 69 7b [2] 66 61 [2] 78 7c [2] 7a 7d [2] 61 7b [2] 7d 7c [2] 61 53 }

  condition:
    any of them
}