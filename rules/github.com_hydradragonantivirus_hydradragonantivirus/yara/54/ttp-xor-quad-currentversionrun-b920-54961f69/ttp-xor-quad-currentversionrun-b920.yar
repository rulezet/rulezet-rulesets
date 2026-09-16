rule TTP_XOR_QUAD_CurrentVersionRun_b920 {
  strings:
    $key_b920 = { ea 4f [2] ce 41 [2] e5 6d [2] cb 4f [2] df 54 [2] d0 4e [2] ce 53 [2] cc 52 [2] d7 54 [2] cb 53 [2] d7 7c }

  condition:
    any of them
}