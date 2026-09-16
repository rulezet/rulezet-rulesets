rule TTP_XOR_QUAD_CurrentVersionRun_db01 {
  strings:
    $key_db01 = { 88 6e [2] ac 60 [2] 87 4c [2] a9 6e [2] bd 75 [2] b2 6f [2] ac 72 [2] ae 73 [2] b5 75 [2] a9 72 [2] b5 5d }

  condition:
    any of them
}