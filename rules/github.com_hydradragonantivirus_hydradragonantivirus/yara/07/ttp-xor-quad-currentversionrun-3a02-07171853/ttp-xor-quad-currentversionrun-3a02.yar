rule TTP_XOR_QUAD_CurrentVersionRun_3a02 {
  strings:
    $key_3a02 = { 69 6d [2] 4d 63 [2] 66 4f [2] 48 6d [2] 5c 76 [2] 53 6c [2] 4d 71 [2] 4f 70 [2] 54 76 [2] 48 71 [2] 54 5e }

  condition:
    any of them
}