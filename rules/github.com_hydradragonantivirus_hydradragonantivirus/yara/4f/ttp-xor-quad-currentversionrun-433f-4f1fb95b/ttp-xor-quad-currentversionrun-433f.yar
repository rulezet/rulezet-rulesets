rule TTP_XOR_QUAD_CurrentVersionRun_433f {
  strings:
    $key_433f = { 10 50 [2] 34 5e [2] 1f 72 [2] 31 50 [2] 25 4b [2] 2a 51 [2] 34 4c [2] 36 4d [2] 2d 4b [2] 31 4c [2] 2d 63 }

  condition:
    any of them
}