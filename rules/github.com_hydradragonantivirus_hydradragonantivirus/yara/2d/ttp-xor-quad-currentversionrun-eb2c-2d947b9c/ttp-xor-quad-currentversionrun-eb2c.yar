rule TTP_XOR_QUAD_CurrentVersionRun_eb2c {
  strings:
    $key_eb2c = { b8 43 [2] 9c 4d [2] b7 61 [2] 99 43 [2] 8d 58 [2] 82 42 [2] 9c 5f [2] 9e 5e [2] 85 58 [2] 99 5f [2] 85 70 }

  condition:
    any of them
}