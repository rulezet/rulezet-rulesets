rule TTP_XOR_QUAD_CurrentVersionRun_0138 {
  strings:
    $key_0138 = { 52 57 [2] 76 59 [2] 5d 75 [2] 73 57 [2] 67 4c [2] 68 56 [2] 76 4b [2] 74 4a [2] 6f 4c [2] 73 4b [2] 6f 64 }

  condition:
    any of them
}