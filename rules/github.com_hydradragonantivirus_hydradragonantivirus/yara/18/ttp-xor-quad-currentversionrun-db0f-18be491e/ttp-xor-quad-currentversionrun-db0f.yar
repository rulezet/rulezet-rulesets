rule TTP_XOR_QUAD_CurrentVersionRun_db0f {
  strings:
    $key_db0f = { 88 60 [2] ac 6e [2] 87 42 [2] a9 60 [2] bd 7b [2] b2 61 [2] ac 7c [2] ae 7d [2] b5 7b [2] a9 7c [2] b5 53 }

  condition:
    any of them
}