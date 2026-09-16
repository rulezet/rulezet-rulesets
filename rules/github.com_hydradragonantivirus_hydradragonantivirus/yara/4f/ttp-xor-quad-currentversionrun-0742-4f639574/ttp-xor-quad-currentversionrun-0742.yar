rule TTP_XOR_QUAD_CurrentVersionRun_0742 {
  strings:
    $key_0742 = { 54 2d [2] 70 23 [2] 5b 0f [2] 75 2d [2] 61 36 [2] 6e 2c [2] 70 31 [2] 72 30 [2] 69 36 [2] 75 31 [2] 69 1e }

  condition:
    any of them
}