rule TTP_XOR_QUAD_CurrentVersionRun_dbe1 {
  strings:
    $key_dbe1 = { 88 8e [2] ac 80 [2] 87 ac [2] a9 8e [2] bd 95 [2] b2 8f [2] ac 92 [2] ae 93 [2] b5 95 [2] a9 92 [2] b5 bd }

  condition:
    any of them
}