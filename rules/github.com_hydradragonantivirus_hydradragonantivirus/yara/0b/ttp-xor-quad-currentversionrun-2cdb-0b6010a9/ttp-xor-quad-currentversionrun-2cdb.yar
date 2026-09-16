rule TTP_XOR_QUAD_CurrentVersionRun_2cdb {
  strings:
    $key_2cdb = { 7f b4 [2] 5b ba [2] 70 96 [2] 5e b4 [2] 4a af [2] 45 b5 [2] 5b a8 [2] 59 a9 [2] 42 af [2] 5e a8 [2] 42 87 }

  condition:
    any of them
}