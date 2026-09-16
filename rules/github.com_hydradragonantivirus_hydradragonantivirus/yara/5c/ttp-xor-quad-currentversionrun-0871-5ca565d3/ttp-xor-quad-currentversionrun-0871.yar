rule TTP_XOR_QUAD_CurrentVersionRun_0871 {
  strings:
    $key_0871 = { 5b 1e [2] 7f 10 [2] 54 3c [2] 7a 1e [2] 6e 05 [2] 61 1f [2] 7f 02 [2] 7d 03 [2] 66 05 [2] 7a 02 [2] 66 2d }

  condition:
    any of them
}