rule TTP_XOR_QUAD_CurrentVersionRun_6e28 {
  strings:
    $key_6e28 = { 3d 47 [2] 19 49 [2] 32 65 [2] 1c 47 [2] 08 5c [2] 07 46 [2] 19 5b [2] 1b 5a [2] 00 5c [2] 1c 5b [2] 00 74 }

  condition:
    any of them
}