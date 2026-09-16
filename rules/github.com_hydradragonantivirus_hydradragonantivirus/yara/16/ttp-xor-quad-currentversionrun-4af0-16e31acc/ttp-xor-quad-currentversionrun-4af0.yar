rule TTP_XOR_QUAD_CurrentVersionRun_4af0 {
  strings:
    $key_4af0 = { 19 9f [2] 3d 91 [2] 16 bd [2] 38 9f [2] 2c 84 [2] 23 9e [2] 3d 83 [2] 3f 82 [2] 24 84 [2] 38 83 [2] 24 ac }

  condition:
    any of them
}