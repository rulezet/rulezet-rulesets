rule TTP_XOR_QUAD_CurrentVersionRun_c525 {
  strings:
    $key_c525 = { 96 4a [2] b2 44 [2] 99 68 [2] b7 4a [2] a3 51 [2] ac 4b [2] b2 56 [2] b0 57 [2] ab 51 [2] b7 56 [2] ab 79 }

  condition:
    any of them
}