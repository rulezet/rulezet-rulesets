rule TTP_XOR_QUAD_CurrentVersionRun_d81e {
  strings:
    $key_d81e = { 8b 71 [2] af 7f [2] 84 53 [2] aa 71 [2] be 6a [2] b1 70 [2] af 6d [2] ad 6c [2] b6 6a [2] aa 6d [2] b6 42 }

  condition:
    any of them
}