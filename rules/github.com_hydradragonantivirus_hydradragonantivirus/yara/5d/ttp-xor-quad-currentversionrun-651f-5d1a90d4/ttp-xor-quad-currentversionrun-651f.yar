rule TTP_XOR_QUAD_CurrentVersionRun_651f {
  strings:
    $key_651f = { 36 70 [2] 12 7e [2] 39 52 [2] 17 70 [2] 03 6b [2] 0c 71 [2] 12 6c [2] 10 6d [2] 0b 6b [2] 17 6c [2] 0b 43 }

  condition:
    any of them
}