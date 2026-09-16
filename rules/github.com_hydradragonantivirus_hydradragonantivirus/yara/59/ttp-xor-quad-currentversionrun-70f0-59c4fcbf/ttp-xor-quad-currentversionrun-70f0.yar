rule TTP_XOR_QUAD_CurrentVersionRun_70f0 {
  strings:
    $key_70f0 = { 23 9f [2] 07 91 [2] 2c bd [2] 02 9f [2] 16 84 [2] 19 9e [2] 07 83 [2] 05 82 [2] 1e 84 [2] 02 83 [2] 1e ac }

  condition:
    any of them
}