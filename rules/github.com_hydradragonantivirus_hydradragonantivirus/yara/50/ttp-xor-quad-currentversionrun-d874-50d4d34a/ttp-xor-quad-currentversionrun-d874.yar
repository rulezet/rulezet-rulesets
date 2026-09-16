rule TTP_XOR_QUAD_CurrentVersionRun_d874 {
  strings:
    $key_d874 = { 8b 1b [2] af 15 [2] 84 39 [2] aa 1b [2] be 00 [2] b1 1a [2] af 07 [2] ad 06 [2] b6 00 [2] aa 07 [2] b6 28 }

  condition:
    any of them
}