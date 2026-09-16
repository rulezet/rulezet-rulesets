rule TTP_XOR_QUAD_CurrentVersionRun_d84a {
  strings:
    $key_d84a = { 8b 25 [2] af 2b [2] 84 07 [2] aa 25 [2] be 3e [2] b1 24 [2] af 39 [2] ad 38 [2] b6 3e [2] aa 39 [2] b6 16 }

  condition:
    any of them
}