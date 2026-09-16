rule TTP_XOR_QUAD_CurrentVersionRun_3f6f {
  strings:
    $key_3f6f = { 6c 00 [2] 48 0e [2] 63 22 [2] 4d 00 [2] 59 1b [2] 56 01 [2] 48 1c [2] 4a 1d [2] 51 1b [2] 4d 1c [2] 51 33 }

  condition:
    any of them
}