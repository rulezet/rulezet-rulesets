rule TTP_XOR_QUAD_CurrentVersionRun_3742 {
  strings:
    $key_3742 = { 64 2d [2] 40 23 [2] 6b 0f [2] 45 2d [2] 51 36 [2] 5e 2c [2] 40 31 [2] 42 30 [2] 59 36 [2] 45 31 [2] 59 1e }

  condition:
    any of them
}