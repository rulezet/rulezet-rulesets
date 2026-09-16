rule TTP_XOR_QUAD_CurrentVersionRun_305e {
  strings:
    $key_305e = { 63 31 [2] 47 3f [2] 6c 13 [2] 42 31 [2] 56 2a [2] 59 30 [2] 47 2d [2] 45 2c [2] 5e 2a [2] 42 2d [2] 5e 02 }

  condition:
    any of them
}