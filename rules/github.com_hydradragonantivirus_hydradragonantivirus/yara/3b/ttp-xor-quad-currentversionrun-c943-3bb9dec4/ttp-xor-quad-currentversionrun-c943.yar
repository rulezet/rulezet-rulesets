rule TTP_XOR_QUAD_CurrentVersionRun_c943 {
  strings:
    $key_c943 = { 9a 2c [2] be 22 [2] 95 0e [2] bb 2c [2] af 37 [2] a0 2d [2] be 30 [2] bc 31 [2] a7 37 [2] bb 30 [2] a7 1f }

  condition:
    any of them
}