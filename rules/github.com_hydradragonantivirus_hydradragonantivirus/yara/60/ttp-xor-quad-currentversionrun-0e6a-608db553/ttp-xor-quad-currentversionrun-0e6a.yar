rule TTP_XOR_QUAD_CurrentVersionRun_0e6a {
  strings:
    $key_0e6a = { 5d 05 [2] 79 0b [2] 52 27 [2] 7c 05 [2] 68 1e [2] 67 04 [2] 79 19 [2] 7b 18 [2] 60 1e [2] 7c 19 [2] 60 36 }

  condition:
    any of them
}