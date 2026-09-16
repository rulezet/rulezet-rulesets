rule TTP_XOR_QUAD_CurrentVersionRun_3d40 {
  strings:
    $key_3d40 = { 6e 2f [2] 4a 21 [2] 61 0d [2] 4f 2f [2] 5b 34 [2] 54 2e [2] 4a 33 [2] 48 32 [2] 53 34 [2] 4f 33 [2] 53 1c }

  condition:
    any of them
}