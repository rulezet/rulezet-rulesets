rule TTP_XOR_QUAD_CurrentVersionRun_cf32 {
  strings:
    $key_cf32 = { 9c 5d [2] b8 53 [2] 93 7f [2] bd 5d [2] a9 46 [2] a6 5c [2] b8 41 [2] ba 40 [2] a1 46 [2] bd 41 [2] a1 6e }

  condition:
    any of them
}