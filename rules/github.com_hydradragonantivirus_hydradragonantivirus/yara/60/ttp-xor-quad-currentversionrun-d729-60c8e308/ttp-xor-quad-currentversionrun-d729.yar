rule TTP_XOR_QUAD_CurrentVersionRun_d729 {
  strings:
    $key_d729 = { 84 46 [2] a0 48 [2] 8b 64 [2] a5 46 [2] b1 5d [2] be 47 [2] a0 5a [2] a2 5b [2] b9 5d [2] a5 5a [2] b9 75 }

  condition:
    any of them
}