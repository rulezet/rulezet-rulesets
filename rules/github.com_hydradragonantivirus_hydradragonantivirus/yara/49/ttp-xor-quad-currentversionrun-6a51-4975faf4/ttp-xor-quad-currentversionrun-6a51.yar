rule TTP_XOR_QUAD_CurrentVersionRun_6a51 {
  strings:
    $key_6a51 = { 39 3e [2] 1d 30 [2] 36 1c [2] 18 3e [2] 0c 25 [2] 03 3f [2] 1d 22 [2] 1f 23 [2] 04 25 [2] 18 22 [2] 04 0d }

  condition:
    any of them
}