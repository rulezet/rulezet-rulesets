rule TTP_XOR_QUAD_CurrentVersionRun_3d22 {
  strings:
    $key_3d22 = { 6e 4d [2] 4a 43 [2] 61 6f [2] 4f 4d [2] 5b 56 [2] 54 4c [2] 4a 51 [2] 48 50 [2] 53 56 [2] 4f 51 [2] 53 7e }

  condition:
    any of them
}