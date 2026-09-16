rule TTP_XOR_QUAD_CurrentVersionRun_db13 {
  strings:
    $key_db13 = { 88 7c [2] ac 72 [2] 87 5e [2] a9 7c [2] bd 67 [2] b2 7d [2] ac 60 [2] ae 61 [2] b5 67 [2] a9 60 [2] b5 4f }

  condition:
    any of them
}