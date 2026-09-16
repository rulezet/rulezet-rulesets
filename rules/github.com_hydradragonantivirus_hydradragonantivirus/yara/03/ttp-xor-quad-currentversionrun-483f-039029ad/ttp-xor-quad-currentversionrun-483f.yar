rule TTP_XOR_QUAD_CurrentVersionRun_483f {
  strings:
    $key_483f = { 1b 50 [2] 3f 5e [2] 14 72 [2] 3a 50 [2] 2e 4b [2] 21 51 [2] 3f 4c [2] 3d 4d [2] 26 4b [2] 3a 4c [2] 26 63 }

  condition:
    any of them
}