rule TTP_XOR_QUAD_CurrentVersionRun_3f62 {
  strings:
    $key_3f62 = { 6c 0d [2] 48 03 [2] 63 2f [2] 4d 0d [2] 59 16 [2] 56 0c [2] 48 11 [2] 4a 10 [2] 51 16 [2] 4d 11 [2] 51 3e }

  condition:
    any of them
}