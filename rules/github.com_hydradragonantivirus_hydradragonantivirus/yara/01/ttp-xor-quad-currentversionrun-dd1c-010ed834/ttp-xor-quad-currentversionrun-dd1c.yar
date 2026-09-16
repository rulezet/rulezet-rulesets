rule TTP_XOR_QUAD_CurrentVersionRun_dd1c {
  strings:
    $key_dd1c = { 8e 73 [2] aa 7d [2] 81 51 [2] af 73 [2] bb 68 [2] b4 72 [2] aa 6f [2] a8 6e [2] b3 68 [2] af 6f [2] b3 40 }

  condition:
    any of them
}