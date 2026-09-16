rule TTP_XOR_QUAD_CurrentVersionRun_554f {
  strings:
    $key_554f = { 06 20 [2] 22 2e [2] 09 02 [2] 27 20 [2] 33 3b [2] 3c 21 [2] 22 3c [2] 20 3d [2] 3b 3b [2] 27 3c [2] 3b 13 }

  condition:
    any of them
}