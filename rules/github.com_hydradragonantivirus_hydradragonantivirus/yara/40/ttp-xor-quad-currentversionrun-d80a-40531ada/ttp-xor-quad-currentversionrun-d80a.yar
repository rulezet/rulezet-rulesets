rule TTP_XOR_QUAD_CurrentVersionRun_d80a {
  strings:
    $key_d80a = { 8b 65 [2] af 6b [2] 84 47 [2] aa 65 [2] be 7e [2] b1 64 [2] af 79 [2] ad 78 [2] b6 7e [2] aa 79 [2] b6 56 }

  condition:
    any of them
}