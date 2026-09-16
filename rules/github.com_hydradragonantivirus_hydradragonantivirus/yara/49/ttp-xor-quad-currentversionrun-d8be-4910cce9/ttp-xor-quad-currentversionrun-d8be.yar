rule TTP_XOR_QUAD_CurrentVersionRun_d8be {
  strings:
    $key_d8be = { 8b d1 [2] af df [2] 84 f3 [2] aa d1 [2] be ca [2] b1 d0 [2] af cd [2] ad cc [2] b6 ca [2] aa cd [2] b6 e2 }

  condition:
    any of them
}