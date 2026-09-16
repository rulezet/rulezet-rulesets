rule TTP_XOR_QUAD_CurrentVersionRun_dd11 {
  strings:
    $key_dd11 = { 8e 7e [2] aa 70 [2] 81 5c [2] af 7e [2] bb 65 [2] b4 7f [2] aa 62 [2] a8 63 [2] b3 65 [2] af 62 [2] b3 4d }

  condition:
    any of them
}