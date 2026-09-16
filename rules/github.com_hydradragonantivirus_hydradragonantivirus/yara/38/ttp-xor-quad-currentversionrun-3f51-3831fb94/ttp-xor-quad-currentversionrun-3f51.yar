rule TTP_XOR_QUAD_CurrentVersionRun_3f51 {
  strings:
    $key_3f51 = { 6c 3e [2] 48 30 [2] 63 1c [2] 4d 3e [2] 59 25 [2] 56 3f [2] 48 22 [2] 4a 23 [2] 51 25 [2] 4d 22 [2] 51 0d }

  condition:
    any of them
}