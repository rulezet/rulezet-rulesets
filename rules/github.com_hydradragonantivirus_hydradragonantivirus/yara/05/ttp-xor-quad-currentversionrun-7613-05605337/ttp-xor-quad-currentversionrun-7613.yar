rule TTP_XOR_QUAD_CurrentVersionRun_7613 {
  strings:
    $key_7613 = { 25 7c [2] 01 72 [2] 2a 5e [2] 04 7c [2] 10 67 [2] 1f 7d [2] 01 60 [2] 03 61 [2] 18 67 [2] 04 60 [2] 18 4f }

  condition:
    any of them
}