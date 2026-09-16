rule TTP_XOR_QUAD_CurrentVersionRun_2e4f {
  strings:
    $key_2e4f = { 7d 20 [2] 59 2e [2] 72 02 [2] 5c 20 [2] 48 3b [2] 47 21 [2] 59 3c [2] 5b 3d [2] 40 3b [2] 5c 3c [2] 40 13 }

  condition:
    any of them
}