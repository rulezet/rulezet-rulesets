rule TTP_XOR_QUAD_CurrentVersionRun_d82e {
  strings:
    $key_d82e = { 8b 41 [2] af 4f [2] 84 63 [2] aa 41 [2] be 5a [2] b1 40 [2] af 5d [2] ad 5c [2] b6 5a [2] aa 5d [2] b6 72 }

  condition:
    any of them
}