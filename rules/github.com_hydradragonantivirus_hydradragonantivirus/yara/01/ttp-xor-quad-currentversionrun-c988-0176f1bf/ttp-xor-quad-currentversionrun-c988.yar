rule TTP_XOR_QUAD_CurrentVersionRun_c988 {
  strings:
    $key_c988 = { 9a e7 [2] be e9 [2] 95 c5 [2] bb e7 [2] af fc [2] a0 e6 [2] be fb [2] bc fa [2] a7 fc [2] bb fb [2] a7 d4 }

  condition:
    any of them
}