rule TTP_XOR_QUAD_CurrentVersionRun_db0e {
  strings:
    $key_db0e = { 88 61 [2] ac 6f [2] 87 43 [2] a9 61 [2] bd 7a [2] b2 60 [2] ac 7d [2] ae 7c [2] b5 7a [2] a9 7d [2] b5 52 }

  condition:
    any of them
}