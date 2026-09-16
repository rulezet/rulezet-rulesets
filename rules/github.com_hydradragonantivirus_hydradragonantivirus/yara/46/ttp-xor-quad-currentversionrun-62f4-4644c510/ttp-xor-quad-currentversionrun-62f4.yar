rule TTP_XOR_QUAD_CurrentVersionRun_62f4 {
  strings:
    $key_62f4 = { 31 9b [2] 15 95 [2] 3e b9 [2] 10 9b [2] 04 80 [2] 0b 9a [2] 15 87 [2] 17 86 [2] 0c 80 [2] 10 87 [2] 0c a8 }

  condition:
    any of them
}