rule TTP_XOR_QUAD_CurrentVersionRun_4851 {
  strings:
    $key_4851 = { 1b 3e [2] 3f 30 [2] 14 1c [2] 3a 3e [2] 2e 25 [2] 21 3f [2] 3f 22 [2] 3d 23 [2] 26 25 [2] 3a 22 [2] 26 0d }

  condition:
    any of them
}