rule TTP_XOR_QUAD_CurrentVersionRun_d331 {
  strings:
    $key_d331 = { 80 5e [2] a4 50 [2] 8f 7c [2] a1 5e [2] b5 45 [2] ba 5f [2] a4 42 [2] a6 43 [2] bd 45 [2] a1 42 [2] bd 6d }

  condition:
    any of them
}