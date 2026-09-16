rule TTP_XOR_QUAD_CurrentVersionRun_5151 {
  strings:
    $key_5151 = { 02 3e [2] 26 30 [2] 0d 1c [2] 23 3e [2] 37 25 [2] 38 3f [2] 26 22 [2] 24 23 [2] 3f 25 [2] 23 22 [2] 3f 0d }

  condition:
    any of them
}