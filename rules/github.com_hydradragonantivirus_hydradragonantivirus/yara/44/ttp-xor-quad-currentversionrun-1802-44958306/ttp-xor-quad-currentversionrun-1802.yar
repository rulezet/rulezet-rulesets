rule TTP_XOR_QUAD_CurrentVersionRun_1802 {
  strings:
    $key_1802 = { 4b 6d [2] 6f 63 [2] 44 4f [2] 6a 6d [2] 7e 76 [2] 71 6c [2] 6f 71 [2] 6d 70 [2] 76 76 [2] 6a 71 [2] 76 5e }

  condition:
    any of them
}