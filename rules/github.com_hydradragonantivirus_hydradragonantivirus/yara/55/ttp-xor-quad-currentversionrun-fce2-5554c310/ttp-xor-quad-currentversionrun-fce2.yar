rule TTP_XOR_QUAD_CurrentVersionRun_fce2 {
  strings:
    $key_fce2 = { af 8d [2] 8b 83 [2] a0 af [2] 8e 8d [2] 9a 96 [2] 95 8c [2] 8b 91 [2] 89 90 [2] 92 96 [2] 8e 91 [2] 92 be }

  condition:
    any of them
}