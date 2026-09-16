rule TTP_XOR_QUAD_CurrentVersionRun_054f {
  strings:
    $key_054f = { 56 20 [2] 72 2e [2] 59 02 [2] 77 20 [2] 63 3b [2] 6c 21 [2] 72 3c [2] 70 3d [2] 6b 3b [2] 77 3c [2] 6b 13 }

  condition:
    any of them
}