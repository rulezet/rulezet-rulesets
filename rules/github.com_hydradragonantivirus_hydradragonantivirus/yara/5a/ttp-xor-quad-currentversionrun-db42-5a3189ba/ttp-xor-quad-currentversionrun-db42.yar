rule TTP_XOR_QUAD_CurrentVersionRun_db42 {
  strings:
    $key_db42 = { 88 2d [2] ac 23 [2] 87 0f [2] a9 2d [2] bd 36 [2] b2 2c [2] ac 31 [2] ae 30 [2] b5 36 [2] a9 31 [2] b5 1e }

  condition:
    any of them
}