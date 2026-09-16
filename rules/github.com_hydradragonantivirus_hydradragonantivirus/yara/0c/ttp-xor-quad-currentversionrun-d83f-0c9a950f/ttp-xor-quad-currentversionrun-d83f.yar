rule TTP_XOR_QUAD_CurrentVersionRun_d83f {
  strings:
    $key_d83f = { 8b 50 [2] af 5e [2] 84 72 [2] aa 50 [2] be 4b [2] b1 51 [2] af 4c [2] ad 4d [2] b6 4b [2] aa 4c [2] b6 63 }

  condition:
    any of them
}