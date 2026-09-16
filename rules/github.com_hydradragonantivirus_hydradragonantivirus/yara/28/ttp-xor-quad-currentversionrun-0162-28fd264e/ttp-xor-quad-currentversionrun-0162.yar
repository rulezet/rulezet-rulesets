rule TTP_XOR_QUAD_CurrentVersionRun_0162 {
  strings:
    $key_0162 = { 52 0d [2] 76 03 [2] 5d 2f [2] 73 0d [2] 67 16 [2] 68 0c [2] 76 11 [2] 74 10 [2] 6f 16 [2] 73 11 [2] 6f 3e }

  condition:
    any of them
}