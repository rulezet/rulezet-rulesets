rule TTP_XOR_QUAD_CurrentVersionRun_d852 {
  strings:
    $key_d852 = { 8b 3d [2] af 33 [2] 84 1f [2] aa 3d [2] be 26 [2] b1 3c [2] af 21 [2] ad 20 [2] b6 26 [2] aa 21 [2] b6 0e }

  condition:
    any of them
}