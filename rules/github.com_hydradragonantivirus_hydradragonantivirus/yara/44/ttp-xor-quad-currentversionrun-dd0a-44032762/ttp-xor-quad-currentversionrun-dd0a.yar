rule TTP_XOR_QUAD_CurrentVersionRun_dd0a {
  strings:
    $key_dd0a = { 8e 65 [2] aa 6b [2] 81 47 [2] af 65 [2] bb 7e [2] b4 64 [2] aa 79 [2] a8 78 [2] b3 7e [2] af 79 [2] b3 56 }

  condition:
    any of them
}