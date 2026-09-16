rule TTP_XOR_QUAD_CurrentVersionRun_e31e {
  strings:
    $key_e31e = { b0 71 [2] 94 7f [2] bf 53 [2] 91 71 [2] 85 6a [2] 8a 70 [2] 94 6d [2] 96 6c [2] 8d 6a [2] 91 6d [2] 8d 42 }

  condition:
    any of them
}