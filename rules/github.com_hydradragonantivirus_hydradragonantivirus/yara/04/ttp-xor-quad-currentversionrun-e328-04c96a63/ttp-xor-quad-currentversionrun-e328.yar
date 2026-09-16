rule TTP_XOR_QUAD_CurrentVersionRun_e328 {
  strings:
    $key_e328 = { b0 47 [2] 94 49 [2] bf 65 [2] 91 47 [2] 85 5c [2] 8a 46 [2] 94 5b [2] 96 5a [2] 8d 5c [2] 91 5b [2] 8d 74 }

  condition:
    any of them
}