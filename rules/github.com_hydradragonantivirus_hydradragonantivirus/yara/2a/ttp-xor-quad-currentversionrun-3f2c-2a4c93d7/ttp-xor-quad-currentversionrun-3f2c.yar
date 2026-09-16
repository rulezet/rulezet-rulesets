rule TTP_XOR_QUAD_CurrentVersionRun_3f2c {
  strings:
    $key_3f2c = { 6c 43 [2] 48 4d [2] 63 61 [2] 4d 43 [2] 59 58 [2] 56 42 [2] 48 5f [2] 4a 5e [2] 51 58 [2] 4d 5f [2] 51 70 }

  condition:
    any of them
}