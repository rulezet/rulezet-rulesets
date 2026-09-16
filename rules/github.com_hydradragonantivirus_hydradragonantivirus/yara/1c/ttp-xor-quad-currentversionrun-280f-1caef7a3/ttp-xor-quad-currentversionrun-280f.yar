rule TTP_XOR_QUAD_CurrentVersionRun_280f {
  strings:
    $key_280f = { 7b 60 [2] 5f 6e [2] 74 42 [2] 5a 60 [2] 4e 7b [2] 41 61 [2] 5f 7c [2] 5d 7d [2] 46 7b [2] 5a 7c [2] 46 53 }

  condition:
    any of them
}