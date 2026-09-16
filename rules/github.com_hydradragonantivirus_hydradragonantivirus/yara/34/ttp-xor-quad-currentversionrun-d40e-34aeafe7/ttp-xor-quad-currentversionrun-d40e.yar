rule TTP_XOR_QUAD_CurrentVersionRun_d40e {
  strings:
    $key_d40e = { 87 61 [2] a3 6f [2] 88 43 [2] a6 61 [2] b2 7a [2] bd 60 [2] a3 7d [2] a1 7c [2] ba 7a [2] a6 7d [2] ba 52 }

  condition:
    any of them
}