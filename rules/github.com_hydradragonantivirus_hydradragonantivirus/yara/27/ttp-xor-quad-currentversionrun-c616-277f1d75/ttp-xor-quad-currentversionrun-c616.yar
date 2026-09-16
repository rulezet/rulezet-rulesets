rule TTP_XOR_QUAD_CurrentVersionRun_c616 {
  strings:
    $key_c616 = { 95 79 [2] b1 77 [2] 9a 5b [2] b4 79 [2] a0 62 [2] af 78 [2] b1 65 [2] b3 64 [2] a8 62 [2] b4 65 [2] a8 4a }

  condition:
    any of them
}