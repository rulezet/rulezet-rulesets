rule TTP_XOR_QUAD_CurrentVersionRun_166f {
  strings:
    $key_166f = { 45 00 [2] 61 0e [2] 4a 22 [2] 64 00 [2] 70 1b [2] 7f 01 [2] 61 1c [2] 63 1d [2] 78 1b [2] 64 1c [2] 78 33 }

  condition:
    any of them
}