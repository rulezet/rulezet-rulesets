rule TTP_XOR_QUAD_CurrentVersionRun_5871 {
  strings:
    $key_5871 = { 0b 1e [2] 2f 10 [2] 04 3c [2] 2a 1e [2] 3e 05 [2] 31 1f [2] 2f 02 [2] 2d 03 [2] 36 05 [2] 2a 02 [2] 36 2d }

  condition:
    any of them
}