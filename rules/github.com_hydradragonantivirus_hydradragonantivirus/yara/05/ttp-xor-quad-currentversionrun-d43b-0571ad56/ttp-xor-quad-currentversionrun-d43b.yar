rule TTP_XOR_QUAD_CurrentVersionRun_d43b {
  strings:
    $key_d43b = { 87 54 [2] a3 5a [2] 88 76 [2] a6 54 [2] b2 4f [2] bd 55 [2] a3 48 [2] a1 49 [2] ba 4f [2] a6 48 [2] ba 67 }

  condition:
    any of them
}