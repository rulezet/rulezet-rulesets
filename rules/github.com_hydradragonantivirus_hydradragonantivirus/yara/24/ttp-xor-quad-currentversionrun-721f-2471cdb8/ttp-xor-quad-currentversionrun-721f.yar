rule TTP_XOR_QUAD_CurrentVersionRun_721f {
  strings:
    $key_721f = { 21 70 [2] 05 7e [2] 2e 52 [2] 00 70 [2] 14 6b [2] 1b 71 [2] 05 6c [2] 07 6d [2] 1c 6b [2] 00 6c [2] 1c 43 }

  condition:
    any of them
}