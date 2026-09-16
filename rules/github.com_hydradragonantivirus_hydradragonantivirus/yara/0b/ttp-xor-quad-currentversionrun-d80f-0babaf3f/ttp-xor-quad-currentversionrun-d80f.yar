rule TTP_XOR_QUAD_CurrentVersionRun_d80f {
  strings:
    $key_d80f = { 8b 60 [2] af 6e [2] 84 42 [2] aa 60 [2] be 7b [2] b1 61 [2] af 7c [2] ad 7d [2] b6 7b [2] aa 7c [2] b6 53 }

  condition:
    any of them
}