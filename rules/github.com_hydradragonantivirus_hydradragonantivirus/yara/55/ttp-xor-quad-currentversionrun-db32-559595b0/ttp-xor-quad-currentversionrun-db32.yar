rule TTP_XOR_QUAD_CurrentVersionRun_db32 {
  strings:
    $key_db32 = { 88 5d [2] ac 53 [2] 87 7f [2] a9 5d [2] bd 46 [2] b2 5c [2] ac 41 [2] ae 40 [2] b5 46 [2] a9 41 [2] b5 6e }

  condition:
    any of them
}