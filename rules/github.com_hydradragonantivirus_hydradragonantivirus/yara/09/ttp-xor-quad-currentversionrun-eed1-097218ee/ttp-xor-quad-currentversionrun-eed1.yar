rule TTP_XOR_QUAD_CurrentVersionRun_eed1 {
  strings:
    $key_eed1 = { bd be [2] 99 b0 [2] b2 9c [2] 9c be [2] 88 a5 [2] 87 bf [2] 99 a2 [2] 9b a3 [2] 80 a5 [2] 9c a2 [2] 80 8d }

  condition:
    any of them
}