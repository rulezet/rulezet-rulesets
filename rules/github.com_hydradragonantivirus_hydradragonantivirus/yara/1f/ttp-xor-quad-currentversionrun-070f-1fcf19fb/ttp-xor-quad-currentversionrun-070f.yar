rule TTP_XOR_QUAD_CurrentVersionRun_070f {
  strings:
    $key_070f = { 54 60 [2] 70 6e [2] 5b 42 [2] 75 60 [2] 61 7b [2] 6e 61 [2] 70 7c [2] 72 7d [2] 69 7b [2] 75 7c [2] 69 53 }

  condition:
    any of them
}