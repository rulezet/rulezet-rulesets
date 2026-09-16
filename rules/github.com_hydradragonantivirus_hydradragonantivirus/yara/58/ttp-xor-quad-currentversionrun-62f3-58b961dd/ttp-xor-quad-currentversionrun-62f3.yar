rule TTP_XOR_QUAD_CurrentVersionRun_62f3 {
  strings:
    $key_62f3 = { 31 9c [2] 15 92 [2] 3e be [2] 10 9c [2] 04 87 [2] 0b 9d [2] 15 80 [2] 17 81 [2] 0c 87 [2] 10 80 [2] 0c af }

  condition:
    any of them
}