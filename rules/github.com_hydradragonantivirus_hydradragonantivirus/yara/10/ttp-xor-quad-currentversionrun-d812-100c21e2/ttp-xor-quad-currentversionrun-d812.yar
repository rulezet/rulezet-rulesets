rule TTP_XOR_QUAD_CurrentVersionRun_d812 {
  strings:
    $key_d812 = { 8b 7d [2] af 73 [2] 84 5f [2] aa 7d [2] be 66 [2] b1 7c [2] af 61 [2] ad 60 [2] b6 66 [2] aa 61 [2] b6 4e }

  condition:
    any of them
}