rule TTP_XOR_QUAD_CurrentVersionRun_ddf8 {
  strings:
    $key_ddf8 = { 8e 97 [2] aa 99 [2] 81 b5 [2] af 97 [2] bb 8c [2] b4 96 [2] aa 8b [2] a8 8a [2] b3 8c [2] af 8b [2] b3 a4 }

  condition:
    any of them
}