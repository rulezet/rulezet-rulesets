rule TTP_XOR_QUAD_CurrentVersionRun_db61 {
  strings:
    $key_db61 = { 88 0e [2] ac 00 [2] 87 2c [2] a9 0e [2] bd 15 [2] b2 0f [2] ac 12 [2] ae 13 [2] b5 15 [2] a9 12 [2] b5 3d }

  condition:
    any of them
}