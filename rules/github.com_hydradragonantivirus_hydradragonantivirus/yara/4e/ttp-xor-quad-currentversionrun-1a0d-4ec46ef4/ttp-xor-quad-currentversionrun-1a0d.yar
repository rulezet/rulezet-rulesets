rule TTP_XOR_QUAD_CurrentVersionRun_1a0d {
  strings:
    $key_1a0d = { 49 62 [2] 6d 6c [2] 46 40 [2] 68 62 [2] 7c 79 [2] 73 63 [2] 6d 7e [2] 6f 7f [2] 74 79 [2] 68 7e [2] 74 51 }

  condition:
    any of them
}