rule TTP_XOR_QUAD_CurrentVersionRun_ccd0 {
  strings:
    $key_ccd0 = { 9f bf [2] bb b1 [2] 90 9d [2] be bf [2] aa a4 [2] a5 be [2] bb a3 [2] b9 a2 [2] a2 a4 [2] be a3 [2] a2 8c }

  condition:
    any of them
}