rule TTP_XOR_QUAD_CurrentVersionRun_6ace {
  strings:
    $key_6ace = { 39 a1 [2] 1d af [2] 36 83 [2] 18 a1 [2] 0c ba [2] 03 a0 [2] 1d bd [2] 1f bc [2] 04 ba [2] 18 bd [2] 04 92 }

  condition:
    any of them
}