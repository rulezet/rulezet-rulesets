rule TTP_XOR_QUAD_CurrentVersionRun_dd3b {
  strings:
    $key_dd3b = { 8e 54 [2] aa 5a [2] 81 76 [2] af 54 [2] bb 4f [2] b4 55 [2] aa 48 [2] a8 49 [2] b3 4f [2] af 48 [2] b3 67 }

  condition:
    any of them
}