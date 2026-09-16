rule TTP_XOR_QUAD_CurrentVersionRun_dd3e {
  strings:
    $key_dd3e = { 8e 51 [2] aa 5f [2] 81 73 [2] af 51 [2] bb 4a [2] b4 50 [2] aa 4d [2] a8 4c [2] b3 4a [2] af 4d [2] b3 62 }

  condition:
    any of them
}