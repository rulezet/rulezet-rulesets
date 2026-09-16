rule TTP_XOR_QUAD_CurrentVersionRun_017f {
  strings:
    $key_017f = { 52 10 [2] 76 1e [2] 5d 32 [2] 73 10 [2] 67 0b [2] 68 11 [2] 76 0c [2] 74 0d [2] 6f 0b [2] 73 0c [2] 6f 23 }

  condition:
    any of them
}