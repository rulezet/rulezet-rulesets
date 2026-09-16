rule TTP_XOR_QUAD_CurrentVersionRun_d86d {
  strings:
    $key_d86d = { 8b 02 [2] af 0c [2] 84 20 [2] aa 02 [2] be 19 [2] b1 03 [2] af 1e [2] ad 1f [2] b6 19 [2] aa 1e [2] b6 31 }

  condition:
    any of them
}