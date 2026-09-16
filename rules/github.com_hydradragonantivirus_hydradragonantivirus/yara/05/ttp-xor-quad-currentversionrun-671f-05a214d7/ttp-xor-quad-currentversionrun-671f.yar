rule TTP_XOR_QUAD_CurrentVersionRun_671f {
  strings:
    $key_671f = { 34 70 [2] 10 7e [2] 3b 52 [2] 15 70 [2] 01 6b [2] 0e 71 [2] 10 6c [2] 12 6d [2] 09 6b [2] 15 6c [2] 09 43 }

  condition:
    any of them
}