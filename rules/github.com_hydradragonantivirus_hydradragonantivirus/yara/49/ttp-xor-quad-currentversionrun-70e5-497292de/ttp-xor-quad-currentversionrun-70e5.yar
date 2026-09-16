rule TTP_XOR_QUAD_CurrentVersionRun_70e5 {
  strings:
    $key_70e5 = { 23 8a [2] 07 84 [2] 2c a8 [2] 02 8a [2] 16 91 [2] 19 8b [2] 07 96 [2] 05 97 [2] 1e 91 [2] 02 96 [2] 1e b9 }

  condition:
    any of them
}