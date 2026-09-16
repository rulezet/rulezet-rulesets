rule TTP_XOR_QUAD_CurrentVersionRun_db4f {
  strings:
    $key_db4f = { 88 20 [2] ac 2e [2] 87 02 [2] a9 20 [2] bd 3b [2] b2 21 [2] ac 3c [2] ae 3d [2] b5 3b [2] a9 3c [2] b5 13 }

  condition:
    any of them
}