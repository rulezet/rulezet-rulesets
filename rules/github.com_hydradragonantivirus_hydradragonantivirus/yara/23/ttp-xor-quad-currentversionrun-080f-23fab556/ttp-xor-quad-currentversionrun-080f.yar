rule TTP_XOR_QUAD_CurrentVersionRun_080f {
  strings:
    $key_080f = { 5b 60 [2] 7f 6e [2] 54 42 [2] 7a 60 [2] 6e 7b [2] 61 61 [2] 7f 7c [2] 7d 7d [2] 66 7b [2] 7a 7c [2] 66 53 }

  condition:
    any of them
}