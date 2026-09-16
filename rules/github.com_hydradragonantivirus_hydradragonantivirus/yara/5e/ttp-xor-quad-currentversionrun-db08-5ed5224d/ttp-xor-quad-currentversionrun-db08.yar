rule TTP_XOR_QUAD_CurrentVersionRun_db08 {
  strings:
    $key_db08 = { 88 67 [2] ac 69 [2] 87 45 [2] a9 67 [2] bd 7c [2] b2 66 [2] ac 7b [2] ae 7a [2] b5 7c [2] a9 7b [2] b5 54 }

  condition:
    any of them
}