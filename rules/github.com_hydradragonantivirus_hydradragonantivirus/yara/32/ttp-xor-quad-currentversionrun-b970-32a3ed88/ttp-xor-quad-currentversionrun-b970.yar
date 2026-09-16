rule TTP_XOR_QUAD_CurrentVersionRun_b970 {
  strings:
    $key_b970 = { ea 1f [2] ce 11 [2] e5 3d [2] cb 1f [2] df 04 [2] d0 1e [2] ce 03 [2] cc 02 [2] d7 04 [2] cb 03 [2] d7 2c }

  condition:
    any of them
}