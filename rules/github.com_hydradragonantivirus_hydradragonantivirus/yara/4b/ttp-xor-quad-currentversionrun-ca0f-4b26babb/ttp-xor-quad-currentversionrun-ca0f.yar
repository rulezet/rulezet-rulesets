rule TTP_XOR_QUAD_CurrentVersionRun_ca0f {
  strings:
    $key_ca0f = { 99 60 [2] bd 6e [2] 96 42 [2] b8 60 [2] ac 7b [2] a3 61 [2] bd 7c [2] bf 7d [2] a4 7b [2] b8 7c [2] a4 53 }

  condition:
    any of them
}