rule TTP_XOR_QUAD_CurrentVersionRun_b91f {
  strings:
    $key_b91f = { ea 70 [2] ce 7e [2] e5 52 [2] cb 70 [2] df 6b [2] d0 71 [2] ce 6c [2] cc 6d [2] d7 6b [2] cb 6c [2] d7 43 }

  condition:
    any of them
}