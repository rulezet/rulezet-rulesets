rule TTP_XOR_QUAD_CurrentVersionRun_6302 {
  strings:
    $key_6302 = { 30 6d [2] 14 63 [2] 3f 4f [2] 11 6d [2] 05 76 [2] 0a 6c [2] 14 71 [2] 16 70 [2] 0d 76 [2] 11 71 [2] 0d 5e }

  condition:
    any of them
}