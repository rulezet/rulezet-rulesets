rule TTP_XOR_QUAD_CurrentVersionRun_3cdb {
  strings:
    $key_3cdb = { 6f b4 [2] 4b ba [2] 60 96 [2] 4e b4 [2] 5a af [2] 55 b5 [2] 4b a8 [2] 49 a9 [2] 52 af [2] 4e a8 [2] 52 87 }

  condition:
    any of them
}