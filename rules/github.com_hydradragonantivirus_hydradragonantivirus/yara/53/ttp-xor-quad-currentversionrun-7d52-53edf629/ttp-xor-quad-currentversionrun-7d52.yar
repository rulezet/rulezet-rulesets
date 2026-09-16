rule TTP_XOR_QUAD_CurrentVersionRun_7d52 {
  strings:
    $key_7d52 = { 2e 3d [2] 0a 33 [2] 21 1f [2] 0f 3d [2] 1b 26 [2] 14 3c [2] 0a 21 [2] 08 20 [2] 13 26 [2] 0f 21 [2] 13 0e }

  condition:
    any of them
}