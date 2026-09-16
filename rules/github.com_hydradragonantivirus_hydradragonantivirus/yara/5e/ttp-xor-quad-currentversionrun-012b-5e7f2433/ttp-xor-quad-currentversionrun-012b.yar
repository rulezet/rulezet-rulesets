rule TTP_XOR_QUAD_CurrentVersionRun_012b {
  strings:
    $key_012b = { 52 44 [2] 76 4a [2] 5d 66 [2] 73 44 [2] 67 5f [2] 68 45 [2] 76 58 [2] 74 59 [2] 6f 5f [2] 73 58 [2] 6f 77 }

  condition:
    any of them
}