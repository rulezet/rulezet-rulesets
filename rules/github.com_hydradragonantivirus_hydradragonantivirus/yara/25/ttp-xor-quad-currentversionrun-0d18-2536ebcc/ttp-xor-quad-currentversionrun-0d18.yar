rule TTP_XOR_QUAD_CurrentVersionRun_0d18 {
  strings:
    $key_0d18 = { 5e 77 [2] 7a 79 [2] 51 55 [2] 7f 77 [2] 6b 6c [2] 64 76 [2] 7a 6b [2] 78 6a [2] 63 6c [2] 7f 6b [2] 63 44 }

  condition:
    any of them
}