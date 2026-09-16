rule TTP_XOR_QUAD_CurrentVersionRun_db6b {
  strings:
    $key_db6b = { 88 04 [2] ac 0a [2] 87 26 [2] a9 04 [2] bd 1f [2] b2 05 [2] ac 18 [2] ae 19 [2] b5 1f [2] a9 18 [2] b5 37 }

  condition:
    any of them
}