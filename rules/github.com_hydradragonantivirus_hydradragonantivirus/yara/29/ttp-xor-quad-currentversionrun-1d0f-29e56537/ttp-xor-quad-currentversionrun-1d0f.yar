rule TTP_XOR_QUAD_CurrentVersionRun_1d0f {
  strings:
    $key_1d0f = { 4e 60 [2] 6a 6e [2] 41 42 [2] 6f 60 [2] 7b 7b [2] 74 61 [2] 6a 7c [2] 68 7d [2] 73 7b [2] 6f 7c [2] 73 53 }

  condition:
    any of them
}