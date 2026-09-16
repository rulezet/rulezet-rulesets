rule TTP_XOR_QUAD_CurrentVersionRun_6b51 {
  strings:
    $key_6b51 = { 38 3e [2] 1c 30 [2] 37 1c [2] 19 3e [2] 0d 25 [2] 02 3f [2] 1c 22 [2] 1e 23 [2] 05 25 [2] 19 22 [2] 05 0d }

  condition:
    any of them
}