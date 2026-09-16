rule TTP_XOR_QUAD_CurrentVersionRun_e55f {
  strings:
    $key_e55f = { b6 30 [2] 92 3e [2] b9 12 [2] 97 30 [2] 83 2b [2] 8c 31 [2] 92 2c [2] 90 2d [2] 8b 2b [2] 97 2c [2] 8b 03 }

  condition:
    any of them
}