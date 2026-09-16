rule TTP_XOR_QUAD_CurrentVersionRun_d870 {
  strings:
    $key_d870 = { 8b 1f [2] af 11 [2] 84 3d [2] aa 1f [2] be 04 [2] b1 1e [2] af 03 [2] ad 02 [2] b6 04 [2] aa 03 [2] b6 2c }

  condition:
    any of them
}