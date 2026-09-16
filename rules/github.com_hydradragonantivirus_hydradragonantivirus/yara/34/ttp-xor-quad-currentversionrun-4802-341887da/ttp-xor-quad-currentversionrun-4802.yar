rule TTP_XOR_QUAD_CurrentVersionRun_4802 {
  strings:
    $key_4802 = { 1b 6d [2] 3f 63 [2] 14 4f [2] 3a 6d [2] 2e 76 [2] 21 6c [2] 3f 71 [2] 3d 70 [2] 26 76 [2] 3a 71 [2] 26 5e }

  condition:
    any of them
}