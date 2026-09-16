rule TTP_XOR_QUAD_CurrentVersionRun_7a02 {
  strings:
    $key_7a02 = { 29 6d [2] 0d 63 [2] 26 4f [2] 08 6d [2] 1c 76 [2] 13 6c [2] 0d 71 [2] 0f 70 [2] 14 76 [2] 08 71 [2] 14 5e }

  condition:
    any of them
}