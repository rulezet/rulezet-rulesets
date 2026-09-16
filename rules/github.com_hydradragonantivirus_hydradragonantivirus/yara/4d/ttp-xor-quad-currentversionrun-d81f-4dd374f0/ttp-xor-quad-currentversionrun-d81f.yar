rule TTP_XOR_QUAD_CurrentVersionRun_d81f {
  strings:
    $key_d81f = { 8b 70 [2] af 7e [2] 84 52 [2] aa 70 [2] be 6b [2] b1 71 [2] af 6c [2] ad 6d [2] b6 6b [2] aa 6c [2] b6 43 }

  condition:
    any of them
}