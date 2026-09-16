rule TTP_XOR_QUAD_CurrentVersionRun_3739 {
  strings:
    $key_3739 = { 64 56 [2] 40 58 [2] 6b 74 [2] 45 56 [2] 51 4d [2] 5e 57 [2] 40 4a [2] 42 4b [2] 59 4d [2] 45 4a [2] 59 65 }

  condition:
    any of them
}