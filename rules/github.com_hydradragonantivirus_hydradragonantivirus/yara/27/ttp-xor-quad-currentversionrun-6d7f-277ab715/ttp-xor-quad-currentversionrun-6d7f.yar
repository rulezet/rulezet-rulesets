rule TTP_XOR_QUAD_CurrentVersionRun_6d7f {
  strings:
    $key_6d7f = { 3e 10 [2] 1a 1e [2] 31 32 [2] 1f 10 [2] 0b 0b [2] 04 11 [2] 1a 0c [2] 18 0d [2] 03 0b [2] 1f 0c [2] 03 23 }

  condition:
    any of them
}