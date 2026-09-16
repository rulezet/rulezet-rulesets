rule TTP_XOR_QUAD_CurrentVersionRun_0d6f {
  strings:
    $key_0d6f = { 5e 00 [2] 7a 0e [2] 51 22 [2] 7f 00 [2] 6b 1b [2] 64 01 [2] 7a 1c [2] 78 1d [2] 63 1b [2] 7f 1c [2] 63 33 }

  condition:
    any of them
}