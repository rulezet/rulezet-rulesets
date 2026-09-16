rule TTP_XOR_QUAD_CurrentVersionRun_db27 {
  strings:
    $key_db27 = { 88 48 [2] ac 46 [2] 87 6a [2] a9 48 [2] bd 53 [2] b2 49 [2] ac 54 [2] ae 55 [2] b5 53 [2] a9 54 [2] b5 7b }

  condition:
    any of them
}