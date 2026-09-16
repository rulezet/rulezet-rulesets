rule TTP_XOR_QUAD_CurrentVersionRun_dfcc {
  strings:
    $key_dfcc = { 8c a3 [2] a8 ad [2] 83 81 [2] ad a3 [2] b9 b8 [2] b6 a2 [2] a8 bf [2] aa be [2] b1 b8 [2] ad bf [2] b1 90 }

  condition:
    any of them
}