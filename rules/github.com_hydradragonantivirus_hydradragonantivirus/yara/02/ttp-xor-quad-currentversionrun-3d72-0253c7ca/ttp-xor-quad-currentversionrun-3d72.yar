rule TTP_XOR_QUAD_CurrentVersionRun_3d72 {
  strings:
    $key_3d72 = { 6e 1d [2] 4a 13 [2] 61 3f [2] 4f 1d [2] 5b 06 [2] 54 1c [2] 4a 01 [2] 48 00 [2] 53 06 [2] 4f 01 [2] 53 2e }

  condition:
    any of them
}