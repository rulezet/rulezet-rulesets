rule TTP_XOR_QUAD_CurrentVersionRun_3f01 {
  strings:
    $key_3f01 = { 6c 6e [2] 48 60 [2] 63 4c [2] 4d 6e [2] 59 75 [2] 56 6f [2] 48 72 [2] 4a 73 [2] 51 75 [2] 4d 72 [2] 51 5d }

  condition:
    any of them
}