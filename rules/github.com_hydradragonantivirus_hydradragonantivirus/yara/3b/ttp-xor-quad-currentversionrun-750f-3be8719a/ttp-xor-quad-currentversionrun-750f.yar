rule TTP_XOR_QUAD_CurrentVersionRun_750f {
  strings:
    $key_750f = { 26 60 [2] 02 6e [2] 29 42 [2] 07 60 [2] 13 7b [2] 1c 61 [2] 02 7c [2] 00 7d [2] 1b 7b [2] 07 7c [2] 1b 53 }

  condition:
    any of them
}