rule TTP_XOR_QUAD_CurrentVersionRun_3d02 {
  strings:
    $key_3d02 = { 6e 6d [2] 4a 63 [2] 61 4f [2] 4f 6d [2] 5b 76 [2] 54 6c [2] 4a 71 [2] 48 70 [2] 53 76 [2] 4f 71 [2] 53 5e }

  condition:
    any of them
}