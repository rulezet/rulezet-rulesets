rule TTP_XOR_QUAD_CurrentVersionRun_6ef0 {
  strings:
    $key_6ef0 = { 3d 9f [2] 19 91 [2] 32 bd [2] 1c 9f [2] 08 84 [2] 07 9e [2] 19 83 [2] 1b 82 [2] 00 84 [2] 1c 83 [2] 00 ac }

  condition:
    any of them
}