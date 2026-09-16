rule TTP_XOR_QUAD_CurrentVersionRun_db29 {
  strings:
    $key_db29 = { 88 46 [2] ac 48 [2] 87 64 [2] a9 46 [2] bd 5d [2] b2 47 [2] ac 5a [2] ae 5b [2] b5 5d [2] a9 5a [2] b5 75 }

  condition:
    any of them
}