rule TTP_XOR_QUAD_CurrentVersionRun_d85f {
  strings:
    $key_d85f = { 8b 30 [2] af 3e [2] 84 12 [2] aa 30 [2] be 2b [2] b1 31 [2] af 2c [2] ad 2d [2] b6 2b [2] aa 2c [2] b6 03 }

  condition:
    any of them
}