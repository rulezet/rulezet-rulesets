rule TTP_XOR_QUAD_CurrentVersionRun_fa0f {
  strings:
    $key_fa0f = { a9 60 [2] 8d 6e [2] a6 42 [2] 88 60 [2] 9c 7b [2] 93 61 [2] 8d 7c [2] 8f 7d [2] 94 7b [2] 88 7c [2] 94 53 }

  condition:
    any of them
}