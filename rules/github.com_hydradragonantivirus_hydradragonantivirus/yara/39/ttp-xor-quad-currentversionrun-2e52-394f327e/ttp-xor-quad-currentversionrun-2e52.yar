rule TTP_XOR_QUAD_CurrentVersionRun_2e52 {
  strings:
    $key_2e52 = { 7d 3d [2] 59 33 [2] 72 1f [2] 5c 3d [2] 48 26 [2] 47 3c [2] 59 21 [2] 5b 20 [2] 40 26 [2] 5c 21 [2] 40 0e }

  condition:
    any of them
}