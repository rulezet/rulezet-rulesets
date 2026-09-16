rule TTP_XOR_QUAD_CurrentVersionRun_581f {
  strings:
    $key_581f = { 0b 70 [2] 2f 7e [2] 04 52 [2] 2a 70 [2] 3e 6b [2] 31 71 [2] 2f 6c [2] 2d 6d [2] 36 6b [2] 2a 6c [2] 36 43 }

  condition:
    any of them
}