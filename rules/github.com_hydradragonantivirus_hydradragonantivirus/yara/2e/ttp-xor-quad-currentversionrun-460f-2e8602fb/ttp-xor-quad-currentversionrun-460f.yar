rule TTP_XOR_QUAD_CurrentVersionRun_460f {
  strings:
    $key_460f = { 15 60 [2] 31 6e [2] 1a 42 [2] 34 60 [2] 20 7b [2] 2f 61 [2] 31 7c [2] 33 7d [2] 28 7b [2] 34 7c [2] 28 53 }

  condition:
    any of them
}