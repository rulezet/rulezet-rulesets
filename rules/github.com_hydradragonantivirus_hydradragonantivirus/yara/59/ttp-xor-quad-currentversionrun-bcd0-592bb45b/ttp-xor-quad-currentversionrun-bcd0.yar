rule TTP_XOR_QUAD_CurrentVersionRun_bcd0 {
  strings:
    $key_bcd0 = { ef bf [2] cb b1 [2] e0 9d [2] ce bf [2] da a4 [2] d5 be [2] cb a3 [2] c9 a2 [2] d2 a4 [2] ce a3 [2] d2 8c }

  condition:
    any of them
}