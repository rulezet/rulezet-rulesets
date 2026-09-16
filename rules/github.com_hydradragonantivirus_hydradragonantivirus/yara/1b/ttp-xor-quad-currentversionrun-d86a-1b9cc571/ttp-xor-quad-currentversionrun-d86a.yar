rule TTP_XOR_QUAD_CurrentVersionRun_d86a {
  strings:
    $key_d86a = { 8b 05 [2] af 0b [2] 84 27 [2] aa 05 [2] be 1e [2] b1 04 [2] af 19 [2] ad 18 [2] b6 1e [2] aa 19 [2] b6 36 }

  condition:
    any of them
}