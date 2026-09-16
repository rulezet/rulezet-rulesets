rule TTP_XOR_QUAD_CurrentVersionRun_db22 {
  strings:
    $key_db22 = { 88 4d [2] ac 43 [2] 87 6f [2] a9 4d [2] bd 56 [2] b2 4c [2] ac 51 [2] ae 50 [2] b5 56 [2] a9 51 [2] b5 7e }

  condition:
    any of them
}