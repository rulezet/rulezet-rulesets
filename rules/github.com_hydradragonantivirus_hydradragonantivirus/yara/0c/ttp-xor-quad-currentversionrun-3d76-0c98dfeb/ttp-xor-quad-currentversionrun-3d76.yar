rule TTP_XOR_QUAD_CurrentVersionRun_3d76 {
  strings:
    $key_3d76 = { 6e 19 [2] 4a 17 [2] 61 3b [2] 4f 19 [2] 5b 02 [2] 54 18 [2] 4a 05 [2] 48 04 [2] 53 02 [2] 4f 05 [2] 53 2a }

  condition:
    any of them
}