rule TTP_XOR_QUAD_CurrentVersionRun_b952 {
  strings:
    $key_b952 = { ea 3d [2] ce 33 [2] e5 1f [2] cb 3d [2] df 26 [2] d0 3c [2] ce 21 [2] cc 20 [2] d7 26 [2] cb 21 [2] d7 0e }

  condition:
    any of them
}