rule TTP_XOR_QUAD_CurrentVersionRun_d716 {
  strings:
    $key_d716 = { 84 79 [2] a0 77 [2] 8b 5b [2] a5 79 [2] b1 62 [2] be 78 [2] a0 65 [2] a2 64 [2] b9 62 [2] a5 65 [2] b9 4a }

  condition:
    any of them
}