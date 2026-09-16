rule TTP_XOR_QUAD_CurrentVersionRun_dca3 {
  strings:
    $key_dca3 = { 8f cc [2] ab c2 [2] 80 ee [2] ae cc [2] ba d7 [2] b5 cd [2] ab d0 [2] a9 d1 [2] b2 d7 [2] ae d0 [2] b2 ff }

  condition:
    any of them
}