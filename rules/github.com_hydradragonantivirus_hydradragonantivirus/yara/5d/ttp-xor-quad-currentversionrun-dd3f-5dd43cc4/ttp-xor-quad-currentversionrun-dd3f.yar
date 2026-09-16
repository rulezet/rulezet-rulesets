rule TTP_XOR_QUAD_CurrentVersionRun_dd3f {
  strings:
    $key_dd3f = { 8e 50 [2] aa 5e [2] 81 72 [2] af 50 [2] bb 4b [2] b4 51 [2] aa 4c [2] a8 4d [2] b3 4b [2] af 4c [2] b3 63 }

  condition:
    any of them
}