rule TTP_XOR_QUAD_CurrentVersionRun_cff0 {
  strings:
    $key_cff0 = { 9c 9f [2] b8 91 [2] 93 bd [2] bd 9f [2] a9 84 [2] a6 9e [2] b8 83 [2] ba 82 [2] a1 84 [2] bd 83 [2] a1 ac }

  condition:
    any of them
}