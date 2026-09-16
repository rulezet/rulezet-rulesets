rule TTP_XOR_QUAD_CurrentVersionRun_386f {
  strings:
    $key_386f = { 6b 00 [2] 4f 0e [2] 64 22 [2] 4a 00 [2] 5e 1b [2] 51 01 [2] 4f 1c [2] 4d 1d [2] 56 1b [2] 4a 1c [2] 56 33 }

  condition:
    any of them
}