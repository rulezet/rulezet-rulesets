rule TTP_XOR_QUAD_CurrentVersionRun_db31 {
  strings:
    $key_db31 = { 88 5e [2] ac 50 [2] 87 7c [2] a9 5e [2] bd 45 [2] b2 5f [2] ac 42 [2] ae 43 [2] b5 45 [2] a9 42 [2] b5 6d }

  condition:
    any of them
}