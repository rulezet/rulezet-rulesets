rule TTP_XOR_QUAD_CurrentVersionRun_dbed {
  strings:
    $key_dbed = { 88 82 [2] ac 8c [2] 87 a0 [2] a9 82 [2] bd 99 [2] b2 83 [2] ac 9e [2] ae 9f [2] b5 99 [2] a9 9e [2] b5 b1 }

  condition:
    any of them
}