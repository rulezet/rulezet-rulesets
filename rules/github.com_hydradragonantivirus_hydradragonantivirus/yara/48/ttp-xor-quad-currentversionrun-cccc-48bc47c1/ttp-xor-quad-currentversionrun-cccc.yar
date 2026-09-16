rule TTP_XOR_QUAD_CurrentVersionRun_cccc {
  strings:
    $key_cccc = { 9f a3 [2] bb ad [2] 90 81 [2] be a3 [2] aa b8 [2] a5 a2 [2] bb bf [2] b9 be [2] a2 b8 [2] be bf [2] a2 90 }

  condition:
    any of them
}