rule TTP_XOR_QUAD_CurrentVersionRun_6b01 {
  strings:
    $key_6b01 = { 38 6e [2] 1c 60 [2] 37 4c [2] 19 6e [2] 0d 75 [2] 02 6f [2] 1c 72 [2] 1e 73 [2] 05 75 [2] 19 72 [2] 05 5d }

  condition:
    any of them
}