rule TTP_XOR_QUAD_CurrentVersionRun_d80c {
  strings:
    $key_d80c = { 8b 63 [2] af 6d [2] 84 41 [2] aa 63 [2] be 78 [2] b1 62 [2] af 7f [2] ad 7e [2] b6 78 [2] aa 7f [2] b6 50 }

  condition:
    any of them
}