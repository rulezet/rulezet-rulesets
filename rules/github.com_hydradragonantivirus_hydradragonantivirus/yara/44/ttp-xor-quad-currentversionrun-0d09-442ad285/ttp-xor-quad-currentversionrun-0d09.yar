rule TTP_XOR_QUAD_CurrentVersionRun_0d09 {
  strings:
    $key_0d09 = { 5e 66 [2] 7a 68 [2] 51 44 [2] 7f 66 [2] 6b 7d [2] 64 67 [2] 7a 7a [2] 78 7b [2] 63 7d [2] 7f 7a [2] 63 55 }

  condition:
    any of them
}