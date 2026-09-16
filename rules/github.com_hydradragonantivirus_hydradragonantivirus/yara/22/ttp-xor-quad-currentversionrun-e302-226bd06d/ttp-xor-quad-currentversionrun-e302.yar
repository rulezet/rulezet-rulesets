rule TTP_XOR_QUAD_CurrentVersionRun_e302 {
  strings:
    $key_e302 = { b0 6d [2] 94 63 [2] bf 4f [2] 91 6d [2] 85 76 [2] 8a 6c [2] 94 71 [2] 96 70 [2] 8d 76 [2] 91 71 [2] 8d 5e }

  condition:
    any of them
}