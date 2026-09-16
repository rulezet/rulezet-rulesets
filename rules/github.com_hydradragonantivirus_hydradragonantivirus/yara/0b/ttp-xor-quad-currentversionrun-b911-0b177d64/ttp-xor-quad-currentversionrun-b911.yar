rule TTP_XOR_QUAD_CurrentVersionRun_b911 {
  strings:
    $key_b911 = { ea 7e [2] ce 70 [2] e5 5c [2] cb 7e [2] df 65 [2] d0 7f [2] ce 62 [2] cc 63 [2] d7 65 [2] cb 62 [2] d7 4d }

  condition:
    any of them
}