rule TTP_XOR_QUAD_CurrentVersionRun_3d58 {
  strings:
    $key_3d58 = { 6e 37 [2] 4a 39 [2] 61 15 [2] 4f 37 [2] 5b 2c [2] 54 36 [2] 4a 2b [2] 48 2a [2] 53 2c [2] 4f 2b [2] 53 04 }

  condition:
    any of them
}