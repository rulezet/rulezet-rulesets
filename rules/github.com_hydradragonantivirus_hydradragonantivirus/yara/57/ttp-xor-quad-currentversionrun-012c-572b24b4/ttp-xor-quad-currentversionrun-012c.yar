rule TTP_XOR_QUAD_CurrentVersionRun_012c {
  strings:
    $key_012c = { 52 43 [2] 76 4d [2] 5d 61 [2] 73 43 [2] 67 58 [2] 68 42 [2] 76 5f [2] 74 5e [2] 6f 58 [2] 73 5f [2] 6f 70 }

  condition:
    any of them
}