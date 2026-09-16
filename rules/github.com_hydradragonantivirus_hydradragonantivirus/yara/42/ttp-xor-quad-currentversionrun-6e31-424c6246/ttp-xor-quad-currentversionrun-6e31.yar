rule TTP_XOR_QUAD_CurrentVersionRun_6e31 {
  strings:
    $key_6e31 = { 3d 5e [2] 19 50 [2] 32 7c [2] 1c 5e [2] 08 45 [2] 07 5f [2] 19 42 [2] 1b 43 [2] 00 45 [2] 1c 42 [2] 00 6d }

  condition:
    any of them
}