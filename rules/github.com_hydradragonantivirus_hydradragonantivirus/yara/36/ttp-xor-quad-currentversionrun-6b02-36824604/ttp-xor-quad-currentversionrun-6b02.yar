rule TTP_XOR_QUAD_CurrentVersionRun_6b02 {
  strings:
    $key_6b02 = { 38 6d [2] 1c 63 [2] 37 4f [2] 19 6d [2] 0d 76 [2] 02 6c [2] 1c 71 [2] 1e 70 [2] 05 76 [2] 19 71 [2] 05 5e }

  condition:
    any of them
}