rule TTP_XOR_QUAD_CurrentVersionRun_015d {
  strings:
    $key_015d = { 52 32 [2] 76 3c [2] 5d 10 [2] 73 32 [2] 67 29 [2] 68 33 [2] 76 2e [2] 74 2f [2] 6f 29 [2] 73 2e [2] 6f 01 }

  condition:
    any of them
}