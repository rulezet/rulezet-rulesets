rule TTP_XOR_QUAD_CurrentVersionRun_961c {
  strings:
    $key_961c = { c5 73 [2] e1 7d [2] ca 51 [2] e4 73 [2] f0 68 [2] ff 72 [2] e1 6f [2] e3 6e [2] f8 68 [2] e4 6f [2] f8 40 }

  condition:
    any of them
}