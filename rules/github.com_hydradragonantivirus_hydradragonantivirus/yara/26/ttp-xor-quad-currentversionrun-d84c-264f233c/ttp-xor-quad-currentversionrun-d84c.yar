rule TTP_XOR_QUAD_CurrentVersionRun_d84c {
  strings:
    $key_d84c = { 8b 23 [2] af 2d [2] 84 01 [2] aa 23 [2] be 38 [2] b1 22 [2] af 3f [2] ad 3e [2] b6 38 [2] aa 3f [2] b6 10 }

  condition:
    any of them
}