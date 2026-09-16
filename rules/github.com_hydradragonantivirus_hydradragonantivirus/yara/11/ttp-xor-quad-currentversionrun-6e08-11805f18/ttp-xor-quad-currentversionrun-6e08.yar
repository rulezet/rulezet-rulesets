rule TTP_XOR_QUAD_CurrentVersionRun_6e08 {
  strings:
    $key_6e08 = { 3d 67 [2] 19 69 [2] 32 45 [2] 1c 67 [2] 08 7c [2] 07 66 [2] 19 7b [2] 1b 7a [2] 00 7c [2] 1c 7b [2] 00 54 }

  condition:
    any of them
}