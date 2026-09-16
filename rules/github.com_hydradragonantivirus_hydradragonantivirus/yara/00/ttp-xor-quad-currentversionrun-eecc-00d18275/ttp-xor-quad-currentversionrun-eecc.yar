rule TTP_XOR_QUAD_CurrentVersionRun_eecc {
  strings:
    $key_eecc = { bd a3 [2] 99 ad [2] b2 81 [2] 9c a3 [2] 88 b8 [2] 87 a2 [2] 99 bf [2] 9b be [2] 80 b8 [2] 9c bf [2] 80 90 }

  condition:
    any of them
}