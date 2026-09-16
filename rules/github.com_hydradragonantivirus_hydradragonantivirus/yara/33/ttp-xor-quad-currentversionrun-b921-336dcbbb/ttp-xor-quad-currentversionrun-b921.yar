rule TTP_XOR_QUAD_CurrentVersionRun_b921 {
  strings:
    $key_b921 = { ea 4e [2] ce 40 [2] e5 6c [2] cb 4e [2] df 55 [2] d0 4f [2] ce 52 [2] cc 53 [2] d7 55 [2] cb 52 [2] d7 7d }

  condition:
    any of them
}