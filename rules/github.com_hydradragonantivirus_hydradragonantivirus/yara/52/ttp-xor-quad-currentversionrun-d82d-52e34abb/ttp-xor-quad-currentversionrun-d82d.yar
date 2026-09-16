rule TTP_XOR_QUAD_CurrentVersionRun_d82d {
  strings:
    $key_d82d = { 8b 42 [2] af 4c [2] 84 60 [2] aa 42 [2] be 59 [2] b1 43 [2] af 5e [2] ad 5f [2] b6 59 [2] aa 5e [2] b6 71 }

  condition:
    any of them
}