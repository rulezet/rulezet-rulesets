rule TTP_XOR_QUAD_CurrentVersionRun_b960 {
  strings:
    $key_b960 = { ea 0f [2] ce 01 [2] e5 2d [2] cb 0f [2] df 14 [2] d0 0e [2] ce 13 [2] cc 12 [2] d7 14 [2] cb 13 [2] d7 3c }

  condition:
    any of them
}