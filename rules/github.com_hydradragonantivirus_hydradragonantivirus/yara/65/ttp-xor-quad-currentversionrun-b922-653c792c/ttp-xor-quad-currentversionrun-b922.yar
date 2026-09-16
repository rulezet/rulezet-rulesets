rule TTP_XOR_QUAD_CurrentVersionRun_b922 {
  strings:
    $key_b922 = { ea 4d [2] ce 43 [2] e5 6f [2] cb 4d [2] df 56 [2] d0 4c [2] ce 51 [2] cc 50 [2] d7 56 [2] cb 51 [2] d7 7e }

  condition:
    any of them
}