rule TTP_XOR_QUAD_CurrentVersionRun_e376 {
  strings:
    $key_e376 = { b0 19 [2] 94 17 [2] bf 3b [2] 91 19 [2] 85 02 [2] 8a 18 [2] 94 05 [2] 96 04 [2] 8d 02 [2] 91 05 [2] 8d 2a }

  condition:
    any of them
}