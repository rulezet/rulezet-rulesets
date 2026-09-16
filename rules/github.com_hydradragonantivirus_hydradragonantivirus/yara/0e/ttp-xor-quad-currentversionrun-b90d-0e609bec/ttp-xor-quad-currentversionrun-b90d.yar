rule TTP_XOR_QUAD_CurrentVersionRun_b90d {
  strings:
    $key_b90d = { ea 62 [2] ce 6c [2] e5 40 [2] cb 62 [2] df 79 [2] d0 63 [2] ce 7e [2] cc 7f [2] d7 79 [2] cb 7e [2] d7 51 }

  condition:
    any of them
}