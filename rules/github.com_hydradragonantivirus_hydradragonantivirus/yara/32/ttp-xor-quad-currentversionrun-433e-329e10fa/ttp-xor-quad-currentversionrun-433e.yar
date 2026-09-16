rule TTP_XOR_QUAD_CurrentVersionRun_433e {
  strings:
    $key_433e = { 10 51 [2] 34 5f [2] 1f 73 [2] 31 51 [2] 25 4a [2] 2a 50 [2] 34 4d [2] 36 4c [2] 2d 4a [2] 31 4d [2] 2d 62 }

  condition:
    any of them
}