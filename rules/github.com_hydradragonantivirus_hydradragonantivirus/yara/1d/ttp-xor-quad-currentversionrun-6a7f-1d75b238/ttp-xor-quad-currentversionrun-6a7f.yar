rule TTP_XOR_QUAD_CurrentVersionRun_6a7f {
  strings:
    $key_6a7f = { 39 10 [2] 1d 1e [2] 36 32 [2] 18 10 [2] 0c 0b [2] 03 11 [2] 1d 0c [2] 1f 0d [2] 04 0b [2] 18 0c [2] 04 23 }

  condition:
    any of them
}