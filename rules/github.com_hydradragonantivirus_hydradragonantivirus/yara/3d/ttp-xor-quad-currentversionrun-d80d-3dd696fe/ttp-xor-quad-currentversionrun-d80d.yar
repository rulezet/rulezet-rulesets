rule TTP_XOR_QUAD_CurrentVersionRun_d80d {
  strings:
    $key_d80d = { 8b 62 [2] af 6c [2] 84 40 [2] aa 62 [2] be 79 [2] b1 63 [2] af 7e [2] ad 7f [2] b6 79 [2] aa 7e [2] b6 51 }

  condition:
    any of them
}