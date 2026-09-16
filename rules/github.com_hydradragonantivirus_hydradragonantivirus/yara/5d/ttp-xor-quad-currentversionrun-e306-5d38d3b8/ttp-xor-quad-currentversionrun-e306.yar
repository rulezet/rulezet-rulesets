rule TTP_XOR_QUAD_CurrentVersionRun_e306 {
  strings:
    $key_e306 = { b0 69 [2] 94 67 [2] bf 4b [2] 91 69 [2] 85 72 [2] 8a 68 [2] 94 75 [2] 96 74 [2] 8d 72 [2] 91 75 [2] 8d 5a }

  condition:
    any of them
}