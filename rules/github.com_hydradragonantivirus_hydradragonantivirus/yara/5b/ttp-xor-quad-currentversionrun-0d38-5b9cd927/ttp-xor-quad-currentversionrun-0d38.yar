rule TTP_XOR_QUAD_CurrentVersionRun_0d38 {
  strings:
    $key_0d38 = { 5e 57 [2] 7a 59 [2] 51 75 [2] 7f 57 [2] 6b 4c [2] 64 56 [2] 7a 4b [2] 78 4a [2] 63 4c [2] 7f 4b [2] 63 64 }

  condition:
    any of them
}