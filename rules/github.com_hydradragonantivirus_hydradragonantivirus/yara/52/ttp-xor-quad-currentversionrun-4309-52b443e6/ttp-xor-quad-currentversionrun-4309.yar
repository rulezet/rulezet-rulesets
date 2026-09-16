rule TTP_XOR_QUAD_CurrentVersionRun_4309 {
  strings:
    $key_4309 = { 10 66 [2] 34 68 [2] 1f 44 [2] 31 66 [2] 25 7d [2] 2a 67 [2] 34 7a [2] 36 7b [2] 2d 7d [2] 31 7a [2] 2d 55 }

  condition:
    any of them
}