rule TTP_XOR_QUAD_CurrentVersionRun_d8f6 {
  strings:
    $key_d8f6 = { 8b 99 [2] af 97 [2] 84 bb [2] aa 99 [2] be 82 [2] b1 98 [2] af 85 [2] ad 84 [2] b6 82 [2] aa 85 [2] b6 aa }

  condition:
    any of them
}