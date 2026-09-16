rule TTP_XOR_QUAD_CurrentVersionRun_dde2 {
  strings:
    $key_dde2 = { 8e 8d [2] aa 83 [2] 81 af [2] af 8d [2] bb 96 [2] b4 8c [2] aa 91 [2] a8 90 [2] b3 96 [2] af 91 [2] b3 be }

  condition:
    any of them
}