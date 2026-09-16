rule TTP_XOR_QUAD_CurrentVersionRun_dadb {
  strings:
    $key_dadb = { 89 b4 [2] ad ba [2] 86 96 [2] a8 b4 [2] bc af [2] b3 b5 [2] ad a8 [2] af a9 [2] b4 af [2] a8 a8 [2] b4 87 }

  condition:
    any of them
}